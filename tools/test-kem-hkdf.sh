#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
module=${PKCS11_TEST_KDF_MODULE:?Set PKCS11_TEST_KDF_MODULE to a trusted libkryoptic_pkcs11.so}
if [[ ! -f "$module" || "$(basename "$module")" != libkryoptic_pkcs11.so ]]; then
    echo 'Use a trusted Kryoptic module with ML-KEM, ML-DSA, ECDH, concatenation, HKDF, SP800-108 and SQLite enabled.' >&2
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
cargo test -p pkcs11-runtime --test montgomery_named_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-client --test montgomery_named_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-runtime --test x25519_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-client --test x25519_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11ctl --test x25519_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-runtime --test x448_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-client --test x448_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11ctl --test x448_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-runtime --test aes_gcm_stream_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-runtime --test ml_dsa_verify_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-client --test ml_dsa_verify_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11ctl --test ml_dsa_signature_first_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-runtime --test aes_cmac_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-client --test aes_cmac_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11ctl --test aes_cmac --locked -- --ignored --test-threads=1
cargo test -p pkcs11-desktop --locked -- software_token_cmac --ignored --test-threads=1
cargo test -p pkcs11-runtime --test kbkdf_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-runtime --test hmac_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-client --test hmac_general_provider --locked -- general_hmac_client --ignored --test-threads=1
cargo test -p pkcs11ctl --test hmac_general --locked -- --ignored --test-threads=1
cargo test -p pkcs11ctl --test mac_multipart_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-desktop --locked -- persistent_hmac_general_desktop --ignored --test-threads=1
cargo test -p pkcs11-client --test kbkdf_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11ctl --test kbkdf --locked -- --ignored --test-threads=1
cargo test -p pkcs11-desktop --locked -- persistent_kbkdf_desktop --ignored --test-threads=1
cargo test -p pkcs11-client --test key_wrap_persistent --locked -- --ignored --test-threads=1
cargo test -p pkcs11ctl --test key_wrap --locked -- --ignored --test-threads=1
cargo test -p pkcs11-desktop --locked -- persistent_aes_wrap_desktop --ignored --test-threads=1
cargo test -p pkcs11-runtime --test signature_stream_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-runtime --test digest_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-client --test digest_provider --locked -- --ignored --test-threads=1
cargo test -p pkcs11-runtime --test hybrid_persistent --locked -- token_hybrid_construction_and_policy --ignored --test-threads=1
cargo test -p pkcs11-client --test ecdh_persistent --locked -- --ignored --test-threads=1
cargo test -p pkcs11-client --test hkdf_persistent --locked -- --ignored --test-threads=1
cargo test -p pkcs11ctl --test key_establishment --locked -- --ignored --test-threads=1
cargo test -p pkcs11-runtime --test hybrid_persistent --locked -- cli_derived_keys_match --ignored --test-threads=1

cargo test -p pkcs11-desktop --locked -- persistent_hkdf_desktop --ignored --test-threads=1

cargo test -p pkcs11-desktop --locked -- persistent_ecdh_desktop --ignored --test-threads=1
