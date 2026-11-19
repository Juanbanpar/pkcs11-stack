#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
if [[ $# != 1 || "$1" != /* ]]; then
    echo 'Usage: build-kem-hkdf-provider.sh /absolute/installation/prefix' >&2
    exit 2
fi
prefix=$1
mkdir -p "$prefix"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-kdf-build.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
source "$(dirname "$(realpath "$0")")/provider-common.sh"
fetch openssl https://github.com/openssl/openssl.git 45e844fa2a14ec92d146bd8f5778ac130b6625fb
cd "$scratch/openssl"
./Configure --prefix="$prefix/openssl" --libdir=lib no-shared no-tests no-docs -fPIC
make -j2
make install_sw
record_openssl
fetch kryoptic https://github.com/latchset/kryoptic.git f997876ff40740992ff3b51d92665e08ac4fbfc2
cd "$scratch/kryoptic"
install_provider_lock
KRYOPTIC_OPENSSL_SOURCES="$scratch/openssl" \
    cargo +"$provider_rust" build --release --locked -p kryoptic --no-default-features --target-dir "$scratch/target" \
    --features kryoptic-lib/aes,kryoptic-lib/mlkem,kryoptic-lib/hkdf,kryoptic-lib/sp800_108,kryoptic-lib/sqlitedb,kryoptic-lib/ecc_min,kryoptic-lib/simplekdf,ossl/ossl-sys
install -m 755 "$scratch/target/release/libkryoptic_pkcs11.so" "$prefix/libkryoptic_pkcs11.so"
install -m 644 LICENSE.txt "$prefix/LICENSE-kryoptic"
install -m 644 "$scratch/openssl/LICENSE.txt" "$prefix/LICENSE-openssl"

record_provider kryoptic "$kryoptic_commit" "$prefix/libkryoptic_pkcs11.so" "aes,mlkem,hkdf,sp800_108,sqlitedb,ecc_min,simplekdf"
