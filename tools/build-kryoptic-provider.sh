#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
if [[ $# != 1 || "$1" != /* ]]; then
    echo 'Usage: build-kryoptic-provider.sh /absolute/installation/prefix' >&2
    exit 2
fi
prefix=$1
mkdir -p "$prefix"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-kryoptic-build.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
source "$(dirname "$(realpath "$0")")/provider-common.sh"
if [[ -n ${KRYOPTIC_OPENSSL_SOURCES:-} ]]; then
    openssl_sources=$(realpath "$KRYOPTIC_OPENSSL_SOURCES")
    verify_openssl "$openssl_sources"
else
    build_openssl
    openssl_sources="$scratch/openssl"
fi
# ossl-sys expects libcrypto.a and include/ at the root of the source path.
# Stage a verified installed prefix without changing its provenance.
openssl_license="$openssl_sources/LICENSE.txt"
if [[ ! -f "$openssl_sources/libcrypto.a" && -f "$openssl_sources/lib/libcrypto.a" ]]; then
    stage="$scratch/openssl-prefix"
    mkdir -p "$stage"
    ln -s "$openssl_sources/include" "$stage/include"
    ln -s "$openssl_sources/lib/libcrypto.a" "$stage/libcrypto.a"
    openssl_sources="$stage"
fi
fetch kryoptic https://github.com/latchset/kryoptic.git f997876ff40740992ff3b51d92665e08ac4fbfc2
cd "$scratch/kryoptic"
install_provider_lock
features=(aes mlkem mldsa slhdsa hkdf sp800_108 sqlitedb ecc_all simplekdf)
KRYOPTIC_OPENSSL_SOURCES="$openssl_sources" \
    cargo +"$provider_rust" build --release --locked -p kryoptic --no-default-features --target-dir "$scratch/target" \
    --features "ossl/ossl-sys ${features[*]/#/kryoptic-lib/}"
install -m 755 "$scratch/target/release/libkryoptic_pkcs11.so" "$prefix/libkryoptic_pkcs11.so"
install -m 644 LICENSE.txt "$prefix/LICENSE-kryoptic"
install -m 644 "$openssl_license" "$prefix/LICENSE-openssl"

profile=$(IFS=,; echo "${features[*]}")
record_provider kryoptic "$kryoptic_commit" "$prefix/libkryoptic_pkcs11.so" "$profile"
