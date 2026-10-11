#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Replaces only the public Stage 5 fixtures. Private keys live in a temporary directory.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
out="$PWD/crates/pkcs11-client/tests/fixtures"
mkdir -p "$out"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
printf 'pkcs11-client independent verification fixture\n' > "$out/message.txt"
for key in rsa p256 p384 p521 ed25519; do
    case "$key" in
        rsa) options=(-newkey rsa:2048) ;;
        p256) options=(-newkey ec -pkeyopt ec_paramgen_curve:prime256v1) ;;
        p384) options=(-newkey ec -pkeyopt ec_paramgen_curve:secp384r1) ;;
        p521) options=(-newkey ec -pkeyopt ec_paramgen_curve:secp521r1) ;;
        ed25519) options=(-newkey ed25519) ;;
    esac
    openssl req -x509 "${options[@]}" -nodes -subj "/CN=pkcs11-client-$key-fixture" \
        -days 1 -keyout "$scratch/$key.pem" -outform DER -out "$out/$key.der" 2>/dev/null
    [[ "$key" != ed25519 ]] || continue
    for digest in sha256 sha384 sha512; do
        openssl dgst "-$digest" -sign "$scratch/$key.pem" \
            -out "$out/$key-$digest.sig" "$out/message.txt"
        if [[ "$key" == rsa ]]; then
            openssl dgst "-$digest" -sign "$scratch/$key.pem" \
                -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20 \
                -out "$out/rsa-pss-$digest.sig" "$out/message.txt"
        fi
    done
done
