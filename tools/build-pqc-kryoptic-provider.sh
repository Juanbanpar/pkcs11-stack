#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
if [[ $# != 1 || "$1" != /* ]]; then
    echo 'Usage: build-pqc-kryoptic-provider.sh /absolute/installation/prefix' >&2
    exit 2
fi
prefix=$1
mkdir -p "$prefix"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-pqc-kryoptic-build.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
fetch() {
    git init "$scratch/$1"
    git -C "$scratch/$1" fetch --depth 1 "$2" "$3"
    git -C "$scratch/$1" checkout --detach FETCH_HEAD
}
if [[ -n ${KRYOPTIC_OPENSSL_SOURCES:-} ]]; then
    openssl_sources=$(realpath "$KRYOPTIC_OPENSSL_SOURCES")
else
    fetch openssl https://github.com/openssl/openssl.git 45e844fa2a14ec92d146bd8f5778ac130b6625fb
    cd "$scratch/openssl"
    ./Configure --prefix="$prefix/openssl" --libdir=lib no-shared no-tests no-docs -fPIC
    make -j2
    make install_sw
    openssl_sources="$scratch/openssl"
fi
# ossl-sys expects libcrypto.a and include/ at the root of the source path.
# Accept an installed OpenSSL prefix as well as a built source tree.
if [[ ! -f "$openssl_sources/libcrypto.a" && -f "$openssl_sources/lib/libcrypto.a" ]]; then
    stage="$scratch/openssl-prefix"
    mkdir -p "$stage"
    ln -s "$openssl_sources/include" "$stage/include"
    ln -s "$openssl_sources/lib/libcrypto.a" "$stage/libcrypto.a"
    openssl_sources="$stage"
fi
fetch kryoptic https://github.com/latchset/kryoptic.git f997876ff40740992ff3b51d92665e08ac4fbfc2
cd "$scratch/kryoptic"
# Upstream has no Cargo.lock. Resolve its dependencies before the locked build.
cargo generate-lockfile
KRYOPTIC_OPENSSL_SOURCES="$openssl_sources" \
    cargo build --release --locked -p kryoptic --no-default-features --target-dir "$scratch/target" \
    --features kryoptic-lib/aes,kryoptic-lib/mlkem,kryoptic-lib/mldsa,kryoptic-lib/slhdsa,kryoptic-lib/sqlitedb,kryoptic-lib/ecc_all,kryoptic-lib/simplekdf,ossl/ossl-sys
install -m 755 "$scratch/target/release/libkryoptic_pkcs11.so" "$prefix/libkryoptic_pkcs11.so"
install -m 644 LICENSE.txt "$prefix/LICENSE-kryoptic"
if [[ -f "$prefix/openssl/LICENSE.txt" ]]; then
    install -m 644 "$prefix/openssl/LICENSE.txt" "$prefix/LICENSE-openssl"
fi
