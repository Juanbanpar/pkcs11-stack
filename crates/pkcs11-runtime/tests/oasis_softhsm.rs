// SPDX-License-Identifier: MIT OR Apache-2.0
//! Digest, HMAC, AES-CMAC and AES-CBC known answers on disposable SoftHSM.

use pkcs11_runtime::{
    AesDecryptRequest, AesEncryptRequest, AesMode, Attribute, Authentication, Error, HashAlgorithm,
    KeyType, MacAlgorithm, Module, ObjectClass, ObjectRef, Pin, SessionMode,
};
use secrecy::SecretString;

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn reference(token: &str, id: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token={token};object={id};type=secret-key")
            .parse()
            .unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn digest_mac_and_aes_block_known_answers() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let module = Module::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=client-test".parse().unwrap())
        .unwrap();
    let pin = SecretString::from("12345678");
    let mut setup = token.open_session(SessionMode::ReadWrite).unwrap();
    setup
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (label, key_type, value, sign, verify, encrypt, decrypt) in [
        (
            "hmac-sha256",
            KeyType::GENERIC_SECRET,
            hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            true,
            true,
            false,
            false,
        ),
        (
            "aes-cmac",
            KeyType::AES,
            hex("2b7e151628aed2a6abf7158809cf4f3c"),
            true,
            true,
            false,
            false,
        ),
        (
            "runtime-aes-cbc",
            KeyType::AES,
            hex("2b7e151628aed2a6abf7158809cf4f3c"),
            false,
            false,
            true,
            true,
        ),
    ] {
        setup
            .create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(key_type),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(sign),
                Attribute::Verify(verify),
                Attribute::Encrypt(encrypt),
                Attribute::Decrypt(decrypt),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Id(label.as_bytes().to_vec()),
                Attribute::Value(value),
            ])
            .unwrap();
    }

    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
    assert_eq!(
        session.digest(HashAlgorithm::Sha256, b"abc").unwrap(),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );

    let hmac = reference("client-test", "hmac-sha256");
    let message = b"The quick brown fox jumps over the lazy dog";
    let tag = session
        .mac(&hmac, MacAlgorithm::HmacSha256, message)
        .unwrap();
    assert_eq!(
        tag,
        hex("f87ad256151fc7b4c5dffa4adb3ebe911a8eeb8a8ebdee3c2a4a8e5f5ec02c32")
    );
    session
        .verify_mac(&hmac, MacAlgorithm::HmacSha256, message, &tag)
        .unwrap();
    assert!(matches!(
        session.verify_mac(&hmac, MacAlgorithm::HmacSha256, b"other", &tag),
        Err(Error::SignatureMismatch)
    ));
    session.info().unwrap();

    let cmac = reference("client-test", "aes-cmac");
    let message = hex("6bc1bee22e409f96e93d7e117393172a");
    let tag = session.mac(&cmac, MacAlgorithm::AesCmac, &message).unwrap();
    assert_eq!(tag, hex("070a16b46b4d4144f79bdd9dd04a287c"));
    session
        .verify_mac(&cmac, MacAlgorithm::AesCmac, &message, &tag)
        .unwrap();

    let aes = reference("client-test", "runtime-aes-cbc");
    let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let plaintext = hex("6bc1bee22e409f96e93d7e117393172a");
    let request = AesEncryptRequest {
        mode: AesMode::Cbc,
        iv: Some(&iv),
        plaintext: &plaintext,
    };
    let ciphertext = session.encrypt_aes(&aes, &request).unwrap();
    assert_eq!(ciphertext, hex("7649abac8119b246cee98e9b12e9197d"));
    let request = AesDecryptRequest {
        mode: AesMode::Cbc,
        iv: Some(&iv),
        ciphertext: &ciphertext,
    };
    assert_eq!(
        session.decrypt_aes(&aes, &request).unwrap().expose_secret(),
        &plaintext
    );
}

use secrecy::ExposeSecret;
