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
# Disposable RSA encryption fixture for independent OAEP interoperability checks.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$scratch/cipher.key" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$scratch/cipher.key" -outform DER -out "$scratch/cipher-private.der"
openssl pkey -in "$scratch/cipher.key" -pubout -outform DER -out "$scratch/cipher-public.der"
args=(--module "$module" --token-label client-test --login --pin 12345678 --id 20 --label cipher --usage-decrypt)
pkcs11-tool "${args[@]}" --write-object "$scratch/cipher-private.der" --type privkey --sensitive >/dev/null 2>&1
pkcs11-tool "${args[@]}" --write-object "$scratch/cipher-public.der" --type pubkey >/dev/null 2>&1
pkcs11-tool --module "$module" --token-label client-test --login --pin 12345678 --id 21 --label cipher-always --usage-decrypt --always-auth --write-object "$scratch/cipher-private.der" --type privkey --sensitive >/dev/null 2>&1
# Derivation and RFC 3394 fixtures; key bytes are public test vectors.
for specification in '30 EC:prime256v1 derive-p256' '31 EC:secp384r1 derive-p384' '32 EC:secp521r1 derive-p521'; do
    read -r id type label <<< "$specification"
    pkcs11-tool --module "$module" --token-label client-test --login --pin 12345678 \
        --keypairgen --key-type "$type" --id "$id" --label "$label" --usage-derive --sensitive >/dev/null 2>&1
done
printf '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f' > "$scratch/wrap-key.bin"
printf '\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff' > "$scratch/wrap-target.bin"
printf '\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c' > "$scratch/cmac-key.bin"
cp "$scratch/wrap-key.bin" "$scratch/hmac-key.bin"
cp "$scratch/cmac-key.bin" "$scratch/cbc-key.bin"
args=(--module "$module" --token-label client-test --login --pin 12345678 --type secrkey --private --sensitive)
pkcs11-tool "${args[@]}" --write-object "$scratch/wrap-key.bin" --key-type AES:32 --id 40 --label wrapping --usage-wrap >/dev/null 2>&1
pkcs11-tool "${args[@]}" --write-object "$scratch/wrap-target.bin" --key-type AES:16 --id 41 --label transferable --usage-decrypt --extractable >/dev/null 2>&1
pkcs11-tool "${args[@]}" --write-object "$scratch/wrap-target.bin" --key-type AES:16 --id 42 --label nonextractable --usage-decrypt >/dev/null 2>&1
# Digest/MAC/AES block fixtures; public test-vector bytes, disposable token.
pkcs11-tool "${args[@]}" --write-object "$scratch/hmac-key.bin" --key-type GENERIC:32 --id 50 --label hmac >/dev/null 2>&1
pkcs11-tool "${args[@]}" --write-object "$scratch/cmac-key.bin" --key-type AES:16 --id 51 --label cmac >/dev/null 2>&1
pkcs11-tool "${args[@]}" --write-object "$scratch/cbc-key.bin" --key-type AES:16 --id 52 --label aes-cbc >/dev/null 2>&1
"${SOFTHSM2_UTIL:-softhsm2-util}" --module "$module" --init-token --free \
    --label admin-client-test --so-pin 87654321 --pin 12345678 >/dev/null
