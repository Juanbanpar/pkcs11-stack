#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
source tools/softhsm-store.sh
export PKCS11_TEST_PQC_OPENSSL=${PKCS11_TEST_PQC_OPENSSL:-openssl}
command -v "$PKCS11_TEST_PQC_OPENSSL" >/dev/null
export PKCS11_CLIENT_TEST_DIR="$scratch/client" PKCS11_TLS_TEST_DIR="$scratch/tls"
mkdir "$PKCS11_CLIENT_TEST_DIR" "$PKCS11_TLS_TEST_DIR"
for label in pqc-test client-test; do
    "$util" --module "$module" --init-token --free --label "$label" --so-pin 87654321 --pin 12345678 >/dev/null
done
cargo test -p pkcs11-runtime --test ml_dsa_softhsm --locked -- --ignored --test-threads=1
cargo test -p pkcs11-client --test ml_dsa_softhsm --locked -- --ignored --test-threads=1
cargo test -p pkcs11ctl --test ml_dsa_softhsm --locked -- --ignored --test-threads=1
cargo test -p pkcs11-rustls-adapter --features tls12 --test ml_dsa_softhsm --locked -- --ignored --test-threads=1
cargo test -p pkcs11-desktop --locked -- ml_dsa --ignored --test-threads=1
