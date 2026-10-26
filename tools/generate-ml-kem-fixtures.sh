#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
out="$PWD/crates/pkcs11-client/tests/fixtures"
openssl=${PKCS11_TEST_PQC_OPENSSL:-openssl}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
for parameter in 512 768 1024; do
    "$openssl" genpkey -algorithm "ML-KEM-$parameter" -out "$scratch/key.pem"
    "$openssl" pkey -in "$scratch/key.pem" -pubout -outform DER -out "$out/mlkem$parameter.spki.der"
done
