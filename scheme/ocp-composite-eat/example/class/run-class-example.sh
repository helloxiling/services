#!/usr/bin/env bash
# Copyright 2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

this_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(realpath "$this_dir/../../../..")
output="$this_dir/.example-output/class"

if docker ps --format '{{.Names}}' | grep -qE '^(keycloak|vts|provisioning|verification|management|coserv)-service$'; then
    echo "a Veraison deployment is already running; stop it before running this example" >&2
    exit 1
fi

cleanup() {
    "$repo/deployments/docker/veraison" stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$output"
mkdir -p "$output"

make -C "$repo/deployments/docker" builder
docker run --rm --entrypoint /usr/local/go/bin/go \
    -e GOCACHE=/tmp/go-build \
    -v "$repo:/src:ro" \
    -v "$output:/out" \
    -v veraison-go-cache:/go/pkg/mod \
    -w /src veraison/builder \
    run -buildvcs=false ./scheme/ocp-composite-eat/example/class/generator/cmd/generate-demo \
    --class --cocli /home/builder/go/bin/cocli --output /out

"$this_dir/verify-class-offline.sh" server-0-good >/dev/null
"$this_dir/verify-class-offline.sh" server-1-good >/dev/null
for scenario in server-0-cross-server server-1-missing-required; do
    set +e
    "$this_dir/verify-class-offline.sh" "$scenario" >/dev/null
    status=$?
    set -e
    if [[ $status -ne 2 ]]; then
        echo "$scenario: expected offline exit 2, got $status" >&2
        exit 1
    fi
done

make -C "$repo" OCP_COMPOSITE_EAT_ENABLED=1 OCP_COMPOSITE_EAT_DEMO_MODE=class docker-deploy

curl --fail --silent --show-error \
    --cacert "$repo/deployments/docker/src/certs/rootCA.crt" \
    --retry 30 --retry-connrefused --retry-all-errors --retry-delay 1 \
    https://localhost:8443/.well-known/veraison/verification >/dev/null

check_http() {
    local scenario=$1
    local expected=$2
    local result
    result=$(mktemp)
    "$this_dir/run-class-demo.sh" "$scenario" > "$result"
    python3 - "$result" "$scenario" "$expected" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
status = result["submods"]["OCP_COMPOSITE_EAT"]["ear.status"]
expected = sys.argv[3]
if (status == "affirming") != (expected == "affirming"):
    raise SystemExit(f"{sys.argv[2]}: unexpected EAR status {status}")
print(f"{sys.argv[2]}: {status}")
PY
    rm -f "$result"
}

check_http server-0-good affirming
check_http server-1-good affirming
check_http server-0-cross-server non-affirming
check_http server-1-missing-required non-affirming