#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
module=${PKCS11_TEST_KDF_MODULE:?Set PKCS11_TEST_KDF_MODULE to a trusted libkryoptic_pkcs11.so}
if [[ ! -f "$module" || "$(basename "$module")" != libkryoptic_pkcs11.so ]]; then
    echo 'Use a trusted Kryoptic module with ML-KEM, HMAC and SQLite enabled.' >&2
    exit 1
fi
module=$(realpath "$module")
command -v pkcs11-tool >/dev/null
export PKCS11_TEST_PQC_OPENSSL=${PKCS11_TEST_PQC_OPENSSL:-openssl}
command -v "$PKCS11_TEST_PQC_OPENSSL" >/dev/null
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-ml-kem.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
export KRYOPTIC_CONF="$scratch/token.conf"
for slot in 0 1; do
    cat >> "$KRYOPTIC_CONF" <<CONFIG
[[slots]]
slot = $slot
dbtype = "sqlite"
dbargs = "$scratch/token-$slot.sql"
CONFIG
done
export PKCS11_TEST_MODULE="$module" PKCS11_TEST_ISOLATED=1
export PKCS11_CLIENT_TEST_DIR="$scratch/client"
mkdir "$PKCS11_CLIENT_TEST_DIR"
labels=(pqc-test client-test)
for slot in 0 1; do
    pkcs11-tool --module "$module" --slot "$slot" --init-token --label "${labels[$slot]}" --so-pin 87654321 >/dev/null
    pkcs11-tool --module "$module" --slot "$slot" --login --login-type so --so-pin 87654321 --init-pin --pin 12345678 >/dev/null
done
cargo test -p pkcs11-runtime --test ml_kem_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-client --test ml_kem_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-desktop --locked -- ml_kem --ignored --test-threads=1
