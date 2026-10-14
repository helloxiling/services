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
artifact_dir="$this_dir/.example-output/class"
bundle="$artifact_dir/$scenario.bundle.cbor"
nonce_hex=$(tr -d '\n' < "$artifact_dir/nonce.hex")

"$this_dir/../../scripts/submit-evidence.sh" --bundle "$bundle" --nonce "$nonce_hex"