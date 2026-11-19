#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
module=${PKCS11_TEST_KRYOPTIC_MODULE:?Set PKCS11_TEST_KRYOPTIC_MODULE to a trusted libkryoptic_pkcs11.so}
if [[ ! -f "$module" || "${module##*/}" != libkryoptic_pkcs11.so ]]; then
    echo 'Use the trusted combined Kryoptic module built by tools/build-kryoptic-provider.sh.' >&2
    exit 1
fi
module=$(realpath "$module")
openssl=${PKCS11_TEST_KRYOPTIC_OPENSSL:?Set PKCS11_TEST_KRYOPTIC_OPENSSL to the pinned OpenSSL binary}
if ! command -v "$openssl" >/dev/null; then
    echo "OpenSSL executable unavailable: $openssl" >&2
    exit 1
fi
if ! command -v pkcs11-tool >/dev/null; then
    echo 'Install OpenSC for pkcs11-tool.' >&2
    exit 1
fi
export PKCS11_TEST_KDF_OPENSSL="$openssl" PKCS11_TEST_PQC_OPENSSL="$openssl"

# Each scenario runs in a subshell with its own configuration and cleanup.
new_store() {
    local slot store
    scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-kryoptic.XXXXXXXX")
    trap 'rm -rf -- "$scratch"' EXIT
    store=$(realpath -- "$scratch")
    case $store in
        *\"*|*\\*|*[[:cntrl:]]*)
            echo 'The temporary directory path cannot be represented in the Kryoptic configuration.' >&2
            exit 2 ;;
    esac
    scratch=$store
    export KRYOPTIC_CONF="$scratch/token.conf"
    for slot in "$@"; do
        cat >> "$KRYOPTIC_CONF" <<CONFIG
[[slots]]
slot = $slot
dbtype = "sqlite"
dbargs = "$scratch/token-$slot.sql"
CONFIG
    done
}

(
    echo 'Kryoptic ML-KEM and public-key interoperability'
    new_store 0 1
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
)

(
    echo 'Kryoptic persistent HKDF, KBKDF and hybrid key establishment'
    new_store 0
    export PKCS11_TEST_KDF_MODULE="$module" PKCS11_TEST_KDF_ISOLATED=1
    export PKCS11_TEST_KDF_DIR="$scratch"
    cargo test -p pkcs11-runtime --test hkdf_persistent --test kbkdf_provider --locked -- --ignored --test-threads=1
    cargo test -p pkcs11ctl --test kbkdf_provider --locked -- --ignored --test-threads=1
    cargo test -p pkcs11-runtime --test hybrid_persistent --locked -- token_hybrid_construction_and_policy --ignored --test-threads=1
    cargo test -p pkcs11-client --test hkdf_persistent --locked -- --ignored --test-threads=1
    cargo test -p pkcs11ctl --test key_establishment --locked -- --ignored --test-threads=1
    # This test compares the keys written by the preceding CLI suite.
    cargo test -p pkcs11-runtime --test hybrid_persistent --locked -- cli_derived_keys_match --ignored --test-threads=1
    cargo test -p pkcs11-desktop --locked -- persistent_hkdf_desktop --ignored --test-threads=1
)

(
    echo 'Kryoptic SLH-DSA, prehash signing and Montgomery agreement'
    new_store 0
    export PKCS11_TEST_PQC_MODULE="$module" PKCS11_TEST_PQC_DIR="$scratch" PKCS11_TEST_PQC_ISOLATED=1
    cargo test -p pkcs11-runtime --test pqc_kryoptic --locked -- --ignored --test-threads=1
    cargo test -p pkcs11ctl --test pqc_kryoptic --locked -- --ignored --test-threads=1
    cargo test -p pkcs11-desktop --locked -- --ignored --test-threads=1 \
        slh_and_hash_pqc_desktop_signing montgomery_desktop_generation_and_agreement
)
