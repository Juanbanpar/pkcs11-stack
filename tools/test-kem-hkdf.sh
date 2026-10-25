#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
module=${PKCS11_TEST_KDF_MODULE:?Set PKCS11_TEST_KDF_MODULE to a trusted libkryoptic_pkcs11.so}
if [[ ! -f "$module" || "$(basename "$module")" != libkryoptic_pkcs11.so ]]; then
    echo 'Use a trusted Kryoptic module with ML-KEM, ECDH, concatenation, HKDF and SQLite enabled.' >&2
    exit 1
fi
module=$(realpath "$module")
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-kdf.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
export KRYOPTIC_CONF="$scratch/token.conf"
cat > "$KRYOPTIC_CONF" <<CONFIG
[[slots]]
slot = 0
dbtype = "sqlite"
dbargs = "$scratch/token.sql"
CONFIG
export PKCS11_TEST_KDF_DIR="$scratch"
export PKCS11_TEST_KDF_MODULE="$module" PKCS11_TEST_KDF_ISOLATED=1
export PKCS11_TEST_KDF_OPENSSL=${PKCS11_TEST_KDF_OPENSSL:-openssl}
command -v "$PKCS11_TEST_KDF_OPENSSL" >/dev/null
cargo test -p pkcs11-runtime --test hkdf_persistent --locked -- --ignored --test-threads=1
cargo test -p pkcs11-runtime --test hybrid_persistent --locked -- token_hybrid_construction_and_policy --ignored --test-threads=1
cargo test -p pkcs11-client --test hkdf_persistent --locked -- --ignored --test-threads=1
