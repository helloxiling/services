#!/usr/bin/env bash
# Copyright 2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

usage() {
    echo "usage: $0 --package DIR --bundle FILE --nonce HEX [--profile URI]" >&2
}

package=
bundle=
nonce=
profile=

while [[ $# -gt 0 ]]; do
    case "$1" in
        --package) package=${2:-}; shift 2 ;;
        --bundle) bundle=${2:-}; shift 2 ;;
        --nonce) nonce=${2:-}; shift 2 ;;
        --profile) profile=${2:-}; shift 2 ;;
        *) usage; exit 1 ;;
    esac
done

if [[ -z "$package" || ! -d "$package" || -z "$bundle" || ! -f "$bundle" ||
      ! "$nonce" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    usage
    exit 1
fi

for required in class-package.json source-roots.pem evidence-roots.pem platform-class.json; do
    if [[ ! -f "$package/$required" ]]; then
        echo "package is missing $required" >&2
        exit 1
    fi
done

if [[ -z "$profile" ]]; then
    profile=$(python3 - "$package/platform-class.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["compositeEatProfile"])
PY
    )
fi

this_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(realpath "$this_dir/../../..")
package=$(realpath "$package")
bundle=$(realpath "$bundle")

docker run --rm --entrypoint go \
    -v "$repo:/src:ro" \
    -v "$package:/package:ro" \
    -v "$bundle:/evidence.cbor:ro" \
    -v /etc/machine-id:/etc/machine-id:ro \
    -w /src -e GOFLAGS=-buildvcs=false veraison/builder:latest \
    run ./scheme/ocp-composite-eat/cmd/composite-verify \
    --class-package /package/class-package.json \
    --endorsement-roots /package/source-roots.pem \
    --evidence-roots /package/evidence-roots.pem \
    --bundle /evidence.cbor \
    --expected-nonce "$nonce" \
    --native-spdm \
    --composite-eat-profile "$profile"