#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

source tools/softhsm-store.sh
command -v openssl >/dev/null
# Deliberately duplicated labels exercise ambiguity. PINs are public disposable
# fixture values, not a model for production PIN input.
for number in 1 2; do
    "$util" --module "$module" --init-token --free --label runtime-test --so-pin 87654321 --pin 12345678 >/dev/null
done
cargo test -p pkcs11-runtime --test softhsm --test signing_softhsm --locked -- --ignored --test-threads=1
# Create application fixtures only after runtime tests finish: those deliberately
# require exactly the two tokens provisioned above.
export PKCS11_CLIENT_TEST_DIR="$scratch/client"
mkdir "$PKCS11_CLIENT_TEST_DIR"
bash tools/provision-client-softhsm.sh
cargo test -p pkcs11-runtime --test key_operations_softhsm --test generation_softhsm --test aes_gcm_provider --locked -- --ignored --test-threads=1
# PQC and persistent HKDF have dedicated required provider runners.
cargo test -p pkcs11-desktop --locked -- --ignored --test-threads=1 --skip persistent_hkdf_desktop --skip ml_dsa --skip ml_kem
bash tools/test-examples.sh client
cargo test -p pkcs11-client --test softhsm --test administration_softhsm --test generation_softhsm --test aes_gcm_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11ctl --test softhsm --test aes_gcm --locked -- --ignored --test-threads=1
export PKCS11_TLS_TEST_DIR="$scratch/tls"
mkdir "$PKCS11_TLS_TEST_DIR"
bash tools/provision-tls-softhsm.sh
bash tools/test-examples.sh tls
cargo test -p pkcs11-rustls-adapter --features tls12 --test softhsm --locked -- --ignored --test-threads=1
