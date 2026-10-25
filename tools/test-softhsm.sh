#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

# Only use a trusted SoftHSM library. All token initialization targets the new
# temporary SOFTHSM2_CONF below, never an operator's existing token directory.
module=${PKCS11_TEST_MODULE:-}
if [[ -z "$module" ]]; then
    for candidate in \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib64/pkcs11/libsofthsm2.so \
        /usr/lib64/softhsm/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so; do
        if [[ -f "$candidate" ]]; then module=$candidate; break; fi
    done
fi
if [[ -z "$module" || ! -f "$module" || "$(basename "$module")" != libsofthsm2.so ]]; then
    echo 'Set PKCS11_TEST_MODULE to a trusted libsofthsm2.so.' >&2
    exit 1
fi
util=${SOFTHSM2_UTIL:-softhsm2-util}
command -v "$util" >/dev/null
command -v openssl >/dev/null
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-stack.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
mkdir "$scratch/tokens"
export SOFTHSM2_CONF="$scratch/softhsm2.conf"
cat > "$SOFTHSM2_CONF" <<CONFIG
directories.tokendir = $scratch/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
CONFIG
export PKCS11_TEST_MODULE="$module"
export PKCS11_TEST_ISOLATED=1
# Deliberately duplicated labels exercise ambiguity. PINs are public disposable
# fixture values, not a model for production PIN input.
for number in 1 2; do
    "$util" --module "$module" --init-token --free --label runtime-test --so-pin 87654321 --pin 12345678 >/dev/null
done
cargo test -p pkcs11-runtime --test softhsm --test signing_softhsm --locked -- --ignored --test-threads=1
if [[ "${PKCS11_TEST_REQUIRE_PQC:-0}" == 1 ]]; then
    export PKCS11_TEST_PQC_OPENSSL=${PKCS11_TEST_PQC_OPENSSL:-openssl}
    command -v "$PKCS11_TEST_PQC_OPENSSL" >/dev/null
    "$util" --module "$module" --init-token --free --label pqc-test --so-pin 87654321 --pin 12345678 >/dev/null
    cargo test -p pkcs11-runtime --test pqc_softhsm --test ml_dsa_softhsm --test ml_kem_softhsm --locked -- --ignored --test-threads=1
fi
# Create application fixtures only after runtime tests finish: those deliberately
# require exactly the two tokens provisioned above.
export PKCS11_CLIENT_TEST_DIR="$scratch/client"
mkdir "$PKCS11_CLIENT_TEST_DIR"
bash tools/provision-client-softhsm.sh
if [[ "${PKCS11_TEST_REQUIRE_PQC:-0}" == 1 ]]; then
    cargo test -p pkcs11-client --test ml_dsa_softhsm --test ml_kem_softhsm --locked -- --ignored --test-threads=1
fi
cargo test -p pkcs11-runtime --test key_operations_softhsm --test generation_softhsm --test aes_gcm_provider --locked -- --ignored --test-threads=1
if [[ "${PKCS11_TEST_DESKTOP:-0}" == 1 ]]; then
    cargo test -p pkcs11-desktop --locked -- --ignored --test-threads=1
fi
bash tools/test-examples.sh client
cargo test -p pkcs11-client --test softhsm --test administration_softhsm --test generation_softhsm --test aes_gcm_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11ctl --test softhsm --test aes_gcm --locked -- --ignored --test-threads=1
if [[ "${PKCS11_TEST_REQUIRE_PQC:-0}" == 1 ]]; then
    cargo test -p pkcs11ctl --test ml_dsa_softhsm --locked -- --ignored --test-threads=1
fi
export PKCS11_TLS_TEST_DIR="$scratch/tls"
mkdir "$PKCS11_TLS_TEST_DIR"
bash tools/provision-tls-softhsm.sh
bash tools/test-examples.sh tls
cargo test -p pkcs11-rustls-adapter --features tls12 --test softhsm --locked -- --ignored --test-threads=1
if [[ "${PKCS11_TEST_REQUIRE_PQC:-0}" == 1 ]]; then
    cargo test -p pkcs11-rustls-adapter --features tls12 --test ml_dsa_softhsm --locked -- --ignored --test-threads=1
fi
