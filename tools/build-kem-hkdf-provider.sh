#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
if [[ $# != 1 || "$1" != /* ]]; then
    echo 'Usage: build-kem-hkdf-provider.sh /absolute/installation/prefix' >&2
    exit 2
fi
prefix=$1
provider_patch=$(realpath "$(dirname "$0")/patches/kryoptic-x25519-bounds.patch")
eddsa_patch=$(realpath "$(dirname "$0")/patches/kryoptic-eddsa-bounds.patch")
chacha_patch=$(realpath "$(dirname "$0")/patches/kryoptic-chacha20-nonce-bits.patch")
generic_patch=$(realpath "$(dirname "$0")/patches/kryoptic-generic-secret-bounds.patch")
mkdir -p "$prefix"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-kdf-build.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
fetch() {
    git init "$scratch/$1"
    git -C "$scratch/$1" fetch --depth 1 "$2" "$3"
    git -C "$scratch/$1" checkout --detach FETCH_HEAD
}
fetch openssl https://github.com/openssl/openssl.git 45e844fa2a14ec92d146bd8f5778ac130b6625fb
cd "$scratch/openssl"
./Configure --prefix="$prefix/openssl" --libdir=lib no-shared no-tests no-docs -fPIC
make -j2
make install_sw
fetch kryoptic https://github.com/latchset/kryoptic.git f997876ff40740992ff3b51d92665e08ac4fbfc2
cd "$scratch/kryoptic"
# PKCS #11 uses 255 field bits for X25519 mechanism bounds. The pinned
# provider used its 256-bit storage width and excluded X25519 from ECDH bounds.
git apply "$provider_patch"
# Edwards mechanism bounds use field bits; retain the separate 32/57-byte
# storage widths used by the provider for raw public keys and private seeds.
git apply "$eddsa_patch"
# Generic-secret generation advertises supported key sizes in bits, not 0/0.
git apply "$generic_patch"
# PKCS #11 encodes the ordinary ChaCha20-Poly1305 nonce length in bits.
git apply "$chacha_patch"
# Upstream has no Cargo.lock. Resolve its dependencies before the locked build.
cargo generate-lockfile
KRYOPTIC_OPENSSL_SOURCES="$scratch/openssl" \
    cargo build --release --locked -p kryoptic --no-default-features --target-dir "$scratch/target" \
    --features kryoptic-lib/chacha20,kryoptic-lib/aes,kryoptic-lib/mlkem,kryoptic-lib/mldsa,kryoptic-lib/slhdsa,kryoptic-lib/hkdf,kryoptic-lib/sqlitedb,kryoptic-lib/ecc_min,kryoptic-lib/ec_montgomery,kryoptic-lib/eddsa,kryoptic-lib/simplekdf,kryoptic-lib/sp800_108,ossl/ossl-sys
install -m 755 "$scratch/target/release/libkryoptic_pkcs11.so" "$prefix/libkryoptic_pkcs11.so"
install -m 644 LICENSE.txt "$prefix/LICENSE-kryoptic"
install -m 644 "$provider_patch" "$prefix/kryoptic-x25519-bounds.patch"
install -m 644 "$eddsa_patch" "$prefix/kryoptic-eddsa-bounds.patch"
install -m 644 "$chacha_patch" "$prefix/kryoptic-chacha20-nonce-bits.patch"
install -m 644 "$generic_patch" "$prefix/kryoptic-generic-secret-bounds.patch"
install -m 644 "$scratch/openssl/LICENSE.txt" "$prefix/LICENSE-openssl"
