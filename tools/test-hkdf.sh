#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
module=${PKCS11_TEST_HKDF_MODULE:-}
if [[ -z "$module" ]]; then
    for candidate in /usr/lib64/libsoftokn3.so /usr/lib/x86_64-linux-gnu/libsoftokn3.so /usr/lib/aarch64-linux-gnu/libsoftokn3.so; do
        if [[ -f "$candidate" ]]; then module=$candidate; break; fi
    done
fi
if [[ -z "$module" || ! -f "$module" ]]; then
    echo 'Set PKCS11_TEST_HKDF_MODULE to an NSS softoken module.' >&2
    exit 1
fi
module=$(realpath "$module")
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
cd "$scratch"
# NSS's ordinary initialization uses volatile session objects without a database.
PKCS11_TEST_HKDF_ISOLATED=1 PKCS11_TEST_HKDF_MODULE="$module" \
    cargo test --manifest-path "$repo/Cargo.toml" -p pkcs11-runtime --test hkdf_provider \
    --locked -- --ignored --test-threads=1
