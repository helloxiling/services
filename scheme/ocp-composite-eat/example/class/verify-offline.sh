#!/usr/bin/env bash
# Copyright 2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

scenario=${1:-good}
this_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(realpath "$this_dir/../../../..")
artifact_dir="scheme/ocp-composite-eat/example/class/.example-output/snapshot"
nonce=$(tr -d '\n' < "$repo/$artifact_dir/nonce.hex")

docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e GOCACHE=/tmp/go-build \
    -e GOMODCACHE=/tmp/go-mod \
    -v "$repo:/src:ro" \
    -w /src \
    golang:1.26 \
    sh -c 'go build -o /tmp/composite-verify ./scheme/ocp-composite-eat/cmd/composite-verify && exec /tmp/composite-verify "$@"' -- \
    --bundle "$artifact_dir/$scenario.bundle.cbor" \
    --platform-corim "$artifact_dir/platform.corim.cose" \
    --endorsement-roots "$artifact_dir/endorsement-roots.pem" \
    --evidence-roots "$artifact_dir/evidence-roots.pem" \
    --expected-nonce "$nonce" \
    --caliptra-compatibility