#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

if [[ $# != 1 || "$1" != /* ]]; then
    echo 'Usage: build-pqc-softhsm.sh /absolute/installation/prefix' >&2
    exit 2
fi
prefix=$1
mkdir -p "$prefix"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-pqc-build.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT

source "$(dirname "$(realpath "$0")")/provider-common.sh"

# OpenSSL 3.5.9; static PIC libraries keep this test module independent of the
# runner's OpenSSL version without changing its library search path.
build_openssl

softhsm_commit=884cb38f3d2012a0447bd5f50dbd29c429987c41
fetch softhsm https://github.com/softhsm/SoftHSMv2.git "$softhsm_commit"
cd "$scratch/softhsm"
sh autogen.sh
./configure --prefix="$prefix" --with-crypto-backend=openssl \
    --with-openssl="$prefix/openssl" --disable-gost --enable-mldsa
make -j2
make install

record_provider softhsm "$softhsm_commit" "$prefix/lib/softhsm/libsofthsm2.so" "openssl,disable-gost,enable-mldsa"
