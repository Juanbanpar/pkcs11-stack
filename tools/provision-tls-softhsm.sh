#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
[[ ${PKCS11_TEST_ISOLATED:-} == 1 && -d ${PKCS11_TLS_TEST_DIR:-} ]]
module=$PKCS11_TEST_MODULE
scratch=$PKCS11_TLS_TEST_DIR
"${SOFTHSM2_UTIL:-softhsm2-util}" --module "$module" --init-token --free \
    --label stage7-test --so-pin 87654321 --pin 12345678 >/dev/null
for ca in ca other-ca; do
    openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=Stage7-$ca" -days 2 \
        -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -keyout "$scratch/$ca.key" -out "$scratch/$ca.pem" 2>/dev/null
    openssl x509 -in "$scratch/$ca.pem" -outform DER -out "$scratch/$ca.der"
done
for spec in '01 RSA:2048 server-rsa serverAuth' '02 EC:prime256v1 server-p256 serverAuth' \
    '03 EC:secp384r1 server-p384 serverAuth' '04 RSA:2048 client-rsa clientAuth' \
    '05 EC:prime256v1 client-p256 clientAuth' '06 RSA:2048 server-always serverAuth' \
    '07 RSA:2048 server-wrong serverAuth' '08 EC:secp521r1 server-p521 serverAuth'; do
    read -r id type label usage <<< "$spec"
    args=(--module "$module" --token-label stage7-test --login --pin 12345678)
    extra=()
    [[ $label != server-always ]] || extra=(--always-auth)
    pkcs11-tool "${args[@]}" --keypairgen --key-type "$type" --id "$id" --label "$label" \
        --usage-sign --sensitive "${extra[@]}" >/dev/null 2>&1
    pkcs11-tool "${args[@]}" --read-object --type pubkey --id "$id" \
        --output-file "$scratch/$label-public.der" >/dev/null 2>&1
    openssl pkey -pubin -inform DER -in "$scratch/$label-public.der" -out "$scratch/$label-public.pem"
    cat > "$scratch/extensions" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=$usage
subjectAltName=DNS:localhost
EXT
    openssl x509 -new -force_pubkey "$scratch/$label-public.pem" -CA "$scratch/ca.pem" \
        -CAkey "$scratch/ca.key" -set_serial "0x$id" -subj "/CN=$label" -days 1 \
        -extfile "$scratch/extensions" -outform DER -out "$scratch/$label.der"
done
rm -- "$scratch/ca.key" "$scratch/other-ca.key"
