#!/usr/bin/env bash
# Copyright 2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

usage() {
    echo "usage: $0 --bundle FILE (--nonce HEX | --nonce-file FILE) [--session ID] [--url URL] [--tls-ca FILE]" >&2
}

bundle=
nonce_hex=
nonce_file=
session=
verification_url=${VERAISON_VERIFICATION_URL:-https://localhost:8443}
this_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(realpath "$this_dir/../../..")
tls_ca=${VERAISON_TLS_CA:-$repo/deployments/docker/src/certs/rootCA.crt}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bundle) bundle=${2:-}; shift 2 ;;
        --nonce) nonce_hex=${2:-}; shift 2 ;;
        --nonce-file) nonce_file=${2:-}; shift 2 ;;
        --session) session=${2:-}; shift 2 ;;
        --url) verification_url=${2:-}; shift 2 ;;
        --tls-ca) tls_ca=${2:-}; shift 2 ;;
        *) usage; exit 1 ;;
    esac
done

if [[ -z "$bundle" || ! -f "$bundle" ]]; then
    usage
    exit 1
fi
if [[ -n "$nonce_hex" && -n "$nonce_file" ]]; then
    echo "configure exactly one of --nonce and --nonce-file" >&2
    exit 1
fi
if [[ -n "$nonce_file" ]]; then
    nonce_hex=$(tr -d '[:space:]' < "$nonce_file")
fi
if [[ -z "$nonce_hex" || ! "$nonce_hex" =~ ^[0-9A-Fa-f]+$ || $((${#nonce_hex} % 2)) -ne 0 ]]; then
    echo "nonce must be a non-empty, even-length hexadecimal value" >&2
    exit 1
fi

nonce_b64url=$(printf '%s' "$nonce_hex" | xxd -r -p | base64 -w0 | tr '+/' '-_' | tr -d '=')
headers=$(mktemp)
response=$(mktemp)
discovery=$(mktemp)
key=$(mktemp)
trap 'rm -f "$headers" "$response" "$discovery" "$key"' EXIT

if [[ -z "$session" ]]; then
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

with open(sys.argv[1], encoding="utf-8") as source:
    discovery = json.load(source)
with open(sys.argv[2], "w", encoding="utf-8") as destination:
    json.dump(discovery["ear-verification-key"], destination)
PY

docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e GOCACHE=/tmp/go-build \
    -v "$repo:/src:ro" \
    -v "$response:/session.json:ro" \
    -v "$key:/ear-key.json:ro" \
    -v veraison-go-cache:/go/pkg/mod \
    -w /src \
    golang:1.26 \
    go run -buildvcs=false ./scheme/ocp-composite-eat/cmd/verify-ear \
    --session /session.json \
    --key /ear-key.json \
    --expected-nonce "$nonce_hex"