#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
module=${PKCS11_TEST_PQC_MODULE:?Set PKCS11_TEST_PQC_MODULE to a trusted libkryoptic_pkcs11.so}
if [[ ! -f "$module" || "$(basename "$module")" != libkryoptic_pkcs11.so ]]; then
    echo 'Use a trusted Kryoptic module with SLH-DSA, HashSLH-DSA, HashML-DSA, ML-DSA, ML-KEM, ECDH, Montgomery and SQLite enabled.' >&2
    exit 1
fi
module=$(realpath "$module")
command -v "${PKCS11_TEST_PQC_OPENSSL:-openssl}" >/dev/null
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-pqc-kryoptic.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
export KRYOPTIC_CONF="$scratch/token.conf"
cat > "$KRYOPTIC_CONF" <<CONFIG
[[slots]]
slot = 0
dbtype = "sqlite"
dbargs = "$scratch/token.sql"
CONFIG
export PKCS11_TEST_PQC_MODULE="$module"
export PKCS11_TEST_PQC_DIR="$scratch"
export PKCS11_TEST_PQC_ISOLATED=1
export PKCS11_TEST_PQC_OPENSSL=${PKCS11_TEST_PQC_OPENSSL:-openssl}
cargo test -p pkcs11-runtime --test pqc_kryoptic --locked -- --ignored --test-threads=1
cargo test -p pkcs11ctl --test pqc_kryoptic --locked -- --ignored --test-threads=1
cargo test -p pkcs11-desktop --locked -- slh_and_hash_pqc_desktop_signing --ignored --test-threads=1
cargo test -p pkcs11-desktop --locked -- montgomery_desktop_generation_and_agreement --ignored --test-threads=1
