#!/usr/bin/env bash
# Copyright 2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

scenario=${1:-mixed-good}
case "$scenario" in
    mixed-good | mixed-spdm-bad-signature | mixed-spdm-replay | mixed-spdm-bad-measurement | mixed-unsupported) ;;
    *)
        echo "unknown scenario: $scenario" >&2
        exit 1
        ;;
esac

this_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
artifact_dir="$this_dir/.example-output/mixed"
bundle="$artifact_dir/$scenario.bundle.cbor"
verification_url=${VERAISON_VERIFICATION_URL:-https://localhost:8443}
repo=$(realpath "$this_dir/../../../..")
tls_ca=${VERAISON_TLS_CA:-$repo/deployments/docker/src/certs/rootCA.crt}
nonce_hex=$(tr -d '\n' < "$artifact_dir/nonce.hex")
nonce_b64url=$(printf '%s' "$nonce_hex" | xxd -r -p | base64 -w0 | tr '+/' '-_' | tr -d '=')
headers=$(mktemp)
response=$(mktemp)
discovery=$(mktemp)
key=$(mktemp)
trap 'rm -f "$headers" "$response" "$discovery" "$key"' EXIT

curl --fail --silent --show-error --cacert "$tls_ca" --max-time 60 \
    --request POST \
    --dump-header "$headers" \
    --header 'Accept: application/vnd.veraison.challenge-response-session+json' \
    "$verification_url/challenge-response/v1/newSession?nonce=$nonce_b64url" \
    > "$response"

session=$(awk 'BEGIN {IGNORECASE=1} /^Location:/ {gsub("\r", "", $2); print $2}' "$headers")
if [[ -z "$session" ]]; then
    echo "verification service did not return a session Location" >&2
    cat "$response" >&2
    exit 1
fi

curl --fail --silent --show-error --cacert "$tls_ca" --max-time 60 \
    --request POST \
    --header 'Accept: application/vnd.veraison.challenge-response-session+json' \
    --header 'Content-Type: application/eat-bun+cbor' \
    --data-binary "@$bundle" \
    "$verification_url/challenge-response/v1/$session" \
    > "$response"

curl --fail --silent --show-error --cacert "$tls_ca" --max-time 60 \
    --header 'Accept: application/vnd.veraison.discovery+json' \
    "$verification_url/.well-known/veraison/verification" \
    > "$discovery"
python3 - "$discovery" "$key" <<'PY'
import json
import sys
discovery = json.load(open(sys.argv[1]))
json.dump(discovery["ear-verification-key"], open(sys.argv[2], "w"))
PY

repo=$(realpath "$this_dir/../../../..")
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e GOCACHE=/tmp/go-build \
    -e GOMODCACHE=/tmp/go-mod \
    -v "$repo:/src:ro" \
    -v "$response:/session.json:ro" \
    -v "$key:/ear-key.json:ro" \
    -w /src \
    golang:1.26 \
    go run ./scheme/ocp-composite-eat/cmd/verify-ear \
    --session /session.json \
    --key /ear-key.json \
    --expected-nonce "$nonce_hex"