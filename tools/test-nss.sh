#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
module=${PKCS11_TEST_NSS_MODULE:-}
if [[ -z "$module" ]]; then
    for candidate in /usr/lib64/libsoftokn3.so /usr/lib/x86_64-linux-gnu/libsoftokn3.so /usr/lib/libsoftokn3.so; do
        if [[ -f "$candidate" ]]; then module=$candidate; break; fi
    done
fi
if [[ ! -f "$module" || "$(basename "$module")" != libsoftokn3.so ]]; then
    echo 'Set PKCS11_TEST_NSS_MODULE to a trusted NSS libsoftokn3.so.' >&2
    exit 1
fi
command -v certutil >/dev/null
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-nss.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
printf '%s\n' 12345678 > "$scratch/pin"
certutil -N -d "sql:$scratch" -f "$scratch/pin"
export NSS_LIB_PARAMS="configdir='sql:$scratch' certPrefix='' keyPrefix='' secmod='' dbTokenDescription='kdf-test' flags=noModDB"
export PKCS11_TEST_KDF_MODULE="$module" PKCS11_TEST_KDF_DIR="$scratch" PKCS11_TEST_KDF_ISOLATED=1 PKCS11_TEST_NSS_ISOLATED=1
export PKCS11_TEST_KDF_OPENSSL=${PKCS11_TEST_KDF_OPENSSL:-openssl}
command -v "$PKCS11_TEST_KDF_OPENSSL" >/dev/null
cargo test -p pkcs11-runtime --test aes_gcm_message_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-client --test aes_gcm_message --locked -- --ignored --test-threads=1
cargo test -p pkcs11-runtime --test kbkdf_provider --locked -- double_pipeline_nss --ignored --test-threads=1
cargo test -p pkcs11-client --test kbkdf_provider --locked -- double_pipeline_nss --ignored --test-threads=1
cargo test -p pkcs11ctl --test kbkdf --locked -- double_pipeline_nss --ignored --test-threads=1
cargo test -p pkcs11-runtime --test kbkdf_provider --locked -- kbkdf_aes_cmac --ignored --test-threads=1
cargo test -p pkcs11-client --test kbkdf_provider --locked -- kbkdf_aes_cmac --ignored --test-threads=1
cargo test -p pkcs11ctl --test kbkdf --locked -- kbkdf_aes_cmac --ignored --test-threads=1
