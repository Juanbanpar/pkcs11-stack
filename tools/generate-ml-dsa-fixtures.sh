#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
out="$PWD/crates/pkcs11-client/tests/fixtures"
openssl=${PKCS11_TEST_PQC_OPENSSL:-openssl}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
cat > "$scratch/openssl.cnf" <<'CONFIG'
[req]
distinguished_name = dn
[dn]
CONFIG
for parameter in 44 65 87; do
    name=mldsa$parameter
    "$openssl" req -config "$scratch/openssl.cnf" -x509 -newkey "ML-DSA-$parameter" -nodes \
        -subj "/CN=pkcs11-client-$name-fixture" -days 1 \
        -keyout "$scratch/$name.pem" -outform DER -out "$out/$name.der"
    "$openssl" pkey -in "$scratch/$name.pem" -pubout -outform DER -out "$out/$name.spki.der"
    "$openssl" pkeyutl -sign -rawin -inkey "$scratch/$name.pem" \
        -in "$out/message.txt" -out "$out/$name.sig"
    "$openssl" pkeyutl -sign -rawin -inkey "$scratch/$name.pem" \
        -in "$out/message.txt" -pkeyopt context-string:fixture-context -out "$out/$name.context.sig"
done
