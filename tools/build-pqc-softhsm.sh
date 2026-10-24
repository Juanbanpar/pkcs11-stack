#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

if [[ $# != 1 || "$1" != /* ]]; then
    echo 'Usage: build-pqc-softhsm.sh /absolute/installation/prefix' >&2
    exit 2
fi
prefix=$1
mkdir -p "$prefix"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-pqc-build.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT

fetch() {
    git init "$scratch/$1"
    git -C "$scratch/$1" fetch --depth 1 "$2" "$3"
    git -C "$scratch/$1" checkout --detach FETCH_HEAD
}

# OpenSSL 3.5.9; static PIC libraries keep this test module independent of the
# runner's OpenSSL version without changing its library search path.
fetch openssl https://github.com/openssl/openssl.git 45e844fa2a14ec92d146bd8f5778ac130b6625fb
cd "$scratch/openssl"
./Configure --prefix="$prefix/openssl" --libdir=lib no-shared no-tests -fPIC
make -j2
make install_sw

fetch softhsm https://github.com/softhsm/SoftHSMv2.git 884cb38f3d2012a0447bd5f50dbd29c429987c41
cd "$scratch/softhsm"
# This revision reports ML-KEM private-key lengths. PKCS#11 3.2 sections
# 6.68.4/5 require public-key bytes for both mechanisms' advertised bounds.
git apply "$source_root/tools/patches/softhsm-mlkem-public-key-bounds.patch"
sh autogen.sh
./configure --prefix="$prefix" --with-crypto-backend=openssl \
    --with-openssl="$prefix/openssl" --disable-gost --enable-mldsa --enable-mlkem
make -j2
make install
