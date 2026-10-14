#!/usr/bin/env bash
# Copyright 2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

scenario=${1:-server-0-good}
case "$scenario" in
    server-0-good | server-1-good | server-0-cross-server | server-1-missing-required) ;;
    *)
        echo "unknown class scenario: $scenario" >&2
        exit 1
        ;;
esac

this_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(realpath "$this_dir/../../../..")
artifact_dir="scheme/ocp-composite-eat/example/class/.example-output/class"
nonce=$(tr -d '\n' < "$repo/$artifact_dir/nonce.hex")

docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e GOCACHE=/tmp/go-build \
    -e GOMODCACHE=/tmp/go-mod \
    -v "$repo:/src:ro" \
    -w /src \
    golang:1.26 \
    sh -c 'go build -buildvcs=false -o /tmp/composite-verify ./scheme/ocp-composite-eat/cmd/composite-verify && exec /tmp/composite-verify "$@"' -- \
    --bundle "$artifact_dir/$scenario.bundle.cbor" \
    --class-package "$artifact_dir/class-package.json" \
    --endorsement-roots "$artifact_dir/source-roots.pem" \
    --evidence-roots "$artifact_dir/evidence-roots.pem" \
    --expected-nonce "$nonce" \
    --native-spdm