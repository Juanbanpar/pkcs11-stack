#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Internal fixture provisioner; invoked only by test-softhsm.sh in its new store.
set -euo pipefail
umask 077
[[ ${PKCS11_TEST_ISOLATED:-} == 1 && -d ${PKCS11_CLIENT_TEST_DIR:-} ]]
module=$PKCS11_TEST_MODULE
scratch=$PKCS11_CLIENT_TEST_DIR
command -v pkcs11-tool >/dev/null
"${SOFTHSM2_UTIL:-softhsm2-util}" --module "$module" --init-token --free \
    --label client-test --so-pin 87654321 --pin 12345678 >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=Client-Test-CA -days 1 \
    -keyout "$scratch/ca.key" -out "$scratch/ca.pem" 2>/dev/null
for specification in '01 RSA:2048 rsa' '02 EC:prime256v1 p256' '03 EC:secp384r1 p384' \
    '04 EC:secp521r1 p521' '05 RSA:2048 wrong' '06 RSA:2048 always' \
    '10 EC:prime256v1 duplicate' '11 EC:prime256v1 duplicate'; do
    read -r id type label <<< "$specification"
    args=(--module "$module" --token-label client-test --login --pin 12345678)
    extra=()
    [[ $label != always ]] || extra=(--always-auth)
    pkcs11-tool "${args[@]}" --keypairgen --key-type "$type" --id "$id" \
        --label "$label" --usage-sign --sensitive "${extra[@]}" >/dev/null 2>&1
    pkcs11-tool "${args[@]}" --read-object --type pubkey --id "$id" \
        --output-file "$scratch/$id-public.der" >/dev/null 2>&1
    openssl pkey -pubin -inform DER -in "$scratch/$id-public.der" -out "$scratch/$id-public.pem"
    openssl x509 -new -force_pubkey "$scratch/$id-public.pem" -CA "$scratch/ca.pem" \
        -CAkey "$scratch/ca.key" -set_serial "0x$id" -subj "/CN=$label" -days 1 \
        -outform DER -out "$scratch/$id-cert.der"
    pkcs11-tool "${args[@]}" --write-object "$scratch/$id-cert.der" --type cert \
        --id "$id" --label "$label" >/dev/null 2>&1
done
rm -- "$scratch/ca.key"
