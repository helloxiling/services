#!/usr/bin/env bash
# Copyright 2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

this_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT

package="$workspace/package"
mkdir -p "$package" "$workspace/bin"
touch "$package/class-package.json" "$package/source-roots.pem" \
    "$package/evidence-roots.pem"

cat >"$workspace/bin/make" <<'EOF'
#!/usr/bin/env bash
if [[ -n ${TEST_DEPLOY_DEST:-} ]]; then
        expected="DEPLOY_DEST=$TEST_DEPLOY_DEST"
        [[ " $* " == *" $expected "* ]] || exit 74
        mkdir -p "$TEST_DEPLOY_DEST/demo"
        cp "$TEST_PACKAGE/class-package.json" "$TEST_DEPLOY_DEST/demo/class-package.json"
        cat >"$TEST_DEPLOY_DEST/config.yaml" <<CONFIG
        composite-eat-profile: '$TEST_PROFILE'
CONFIG
        exit 0
fi
exit 73
EOF
chmod +x "$workspace/bin/make"

marker="$workspace/make-expansion-ran"
# shellcheck disable=SC2016 # Deliberately exercise a literal Make function.
printf '{"compositeEatProfile":"$(shell touch %s)"}\n' "$marker" \
    >"$package/platform-class.json"

set +e
PATH="$workspace/bin:$PATH" "$this_dir/check-package-deployment.sh" \
    --package "$package" >/dev/null 2>&1
status=$?
set -e

if [[ $status -eq 0 || $status -eq 73 || -e "$marker" ]]; then
    echo "unsafe profile reached make expansion" >&2
    exit 1
fi

printf '{"compositeEatProfile":"https://example.com/composite-eat-01"}\n' \
    >"$package/platform-class.json"

set +e
PATH="$workspace/bin:$PATH" "$this_dir/check-package-deployment.sh" \
    --package "$package" >/dev/null 2>&1
status=$?
set -e

if [[ $status -ne 73 ]]; then
    echo "valid profile did not reach make" >&2
    exit 1
fi

deploy_dest="$workspace/custom-deploy"
TEST_DEPLOY_DEST="$deploy_dest" \
TEST_PACKAGE="$package" \
TEST_PROFILE="https://example.com/composite-eat-01" \
DEPLOY_DEST="$deploy_dest" \
PATH="$workspace/bin:$PATH" "$this_dir/check-package-deployment.sh" \
    --package "$package" >/dev/null

echo "package profile validation passed"
