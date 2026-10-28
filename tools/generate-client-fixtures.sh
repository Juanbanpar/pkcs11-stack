#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Generate public verification fixtures; remove temporary private keys on exit.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
out="$PWD/crates/pkcs11-client/tests/fixtures"
keys=(rsa p256 p384 p521 ed25519)
digests=(sha256 sha384 sha512)
if [[ "${1:-}" == sha224 ]]; then
    out="$out/sha224"
    digests=(sha224)
    keys=(rsa p256 p384 p521)
elif [[ "${1:-}" == sha3 ]]; then
    out="$out/sha3"
    digests=(sha3-224 sha3-256 sha3-384 sha3-512)
    keys=(rsa p256 p384 p521)
elif [[ "${1:-}" == eddsa ]]; then
    out="$out/eddsa"
    keys=(ed25519 ed448)
elif [[ $# != 0 ]]; then
    exit 2
fi
mkdir -p "$out"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
printf 'pkcs11-client independent verification fixture\n' > "$out/message.txt"
for key in "${keys[@]}"; do
    case "$key" in
        rsa) options=(-newkey rsa:2048) ;;
        p256) options=(-newkey ec -pkeyopt ec_paramgen_curve:prime256v1) ;;
        p384) options=(-newkey ec -pkeyopt ec_paramgen_curve:secp384r1) ;;
        p521) options=(-newkey ec -pkeyopt ec_paramgen_curve:secp521r1) ;;
        ed25519|ed448) options=(-newkey "$key") ;;
    esac
    openssl req -x509 "${options[@]}" -nodes -subj "/CN=pkcs11-client-$key-fixture" \
        -days 1 -keyout "$scratch/$key.pem" -outform DER -out "$out/$key.der" 2>/dev/null
    if [[ "${1:-}" == eddsa ]]; then
        openssl pkeyutl -sign -rawin -inkey "$scratch/$key.pem" -in "$out/message.txt" -out "$out/$key.sig"
        continue
    fi
    [[ "$key" != ed25519 ]] || continue
    for digest in "${digests[@]}"; do
        openssl dgst "-$digest" -sign "$scratch/$key.pem" \
            -out "$out/$key-$digest.sig" "$out/message.txt"
        if [[ "$key" == rsa ]]; then
            openssl dgst "-$digest" -sign "$scratch/$key.pem" \
                -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20 \
                -out "$out/rsa-pss-$digest.sig" "$out/message.txt"
        fi
    done
done
