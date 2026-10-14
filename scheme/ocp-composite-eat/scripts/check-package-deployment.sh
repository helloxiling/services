#!/usr/bin/env bash
# Copyright 2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

usage() {
    echo "usage: $0 --package DIR [--profile URI]" >&2
}

package=
profile=

while [[ $# -gt 0 ]]; do
    case "$1" in
        --package) package=${2:-}; shift 2 ;;
        --profile) profile=${2:-}; shift 2 ;;
        *) usage; exit 1 ;;
    esac
done

if [[ -z "$package" || ! -d "$package" ]]; then
    usage
    exit 1
fi
for required in class-package.json source-roots.pem evidence-roots.pem platform-class.json; do
    if [[ ! -f "$package/$required" ]]; then
        echo "package is missing $required" >&2
        exit 1
    fi
done

profile=$(python3 - "$package/platform-class.json" "$profile" <<'PY'
import json
import re
import sys

profile = sys.argv[2]
if not profile:
    with open(sys.argv[1], encoding="utf-8") as source:
        profile = json.load(source)["compositeEatProfile"]

if not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9._~:/?#\[\]@!%&*+,;=-]+", profile):
    raise SystemExit("composite EAT profile must be a URI without whitespace or shell metacharacters")

print(profile)
PY
)

this_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(realpath "$this_dir/../../..")
package=$(realpath "$package")
deploy_dir=${DEPLOY_DEST:-/tmp/veraison}

make -C "$repo/deployments/docker" \
    DEPLOY_DEST="$deploy_dir" \
    OCP_COMPOSITE_EAT_ENABLED=1 \
    OCP_COMPOSITE_EAT_DEMO_MODE=class \
    OCP_COMPOSITE_EAT_PACKAGE_DIR="$package" \
    OCP_COMPOSITE_EAT_PROFILE="$profile" \
    deploy

cmp "$package/class-package.json" "$deploy_dir/demo/class-package.json"
grep -F "    composite-eat-profile: '$profile'" "$deploy_dir/config.yaml" >/dev/null
echo "custom package deployment check passed"