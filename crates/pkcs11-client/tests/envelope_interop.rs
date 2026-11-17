// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public synthetic AES material shared only between two disposable test providers.
use pkcs11_client::{
    AesGcmDecryptRequest, AesGcmEnvelope, Attribute, Authentication, KeyType, Module,
    NonceSequence, ObjectClass, ObjectRef, Pin, Provider, SessionMode,
};
use secrecy::{ExposeSecret, SecretString};

#[test]
#[ignore = "requires tools/test-envelope-interop.sh disposable stores"]
fn softhsm_and_kryoptic_exchange_managed_envelopes() {
    assert_eq!(
        std::env::var("PKCS11_ENVELOPE_ISOLATED").as_deref(),
        Ok("1")
    );
    let paths = [
        std::env::var_os("PKCS11_TEST_MODULE").unwrap(),
        std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap(),
    ];
    let token = "pkcs11:token=envelope-interop".parse().unwrap();
    let pin = SecretString::from("12345678");
    let so = SecretString::from("87654321");
    for path in &paths {
        let mut module = Module::load(path).unwrap();
        let slots = module.slots(true).unwrap();
        assert_eq!(slots.len(), 1);
        module
            .initialize_token(slots[0], &so, "envelope-interop")
            .unwrap();
        let resolved = module.resolve_token_uri(&token).unwrap();
        let mut session = resolved.open_session(SessionMode::ReadWrite).unwrap();
        session
            .authenticate(Authentication::SecurityOfficer(Pin::Value(&so)))
            .unwrap();
        session.initialize_pin(&pin).unwrap();
        session.logout().unwrap();
        session
            .authenticate(Authentication::User(Pin::Value(&pin)))
            .unwrap();
        for (index, length) in [16, 24, 32].into_iter().enumerate() {
            session
                .create_object(&[
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::AES),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                    Attribute::Id(vec![0xE9, index as u8]),
                    Attribute::Value(vec![0x42; length]),
                ])
                .unwrap();
        }
        session.close().unwrap();
        module.finalize().unwrap();
    }
    let root = std::path::PathBuf::from(std::env::var_os("PKCS11_ENVELOPE_DIR").unwrap());
    for index in 0..3 {
        let key = ObjectRef::new(
            format!("pkcs11:token=envelope-interop;id=%E9%{index:02X};type=secret-key")
                .parse()
                .unwrap(),
        )
        .unwrap();
        // The imported copies are new and every encryption shares this one authority.
        let mut state =
            NonceSequence::create(root.join(format!("key-{index}.state")), &key).unwrap();
        for (writer, path) in paths.iter().enumerate() {
            let provider = Provider::load(path).unwrap();
            let mut session = provider
                .management(
                    &token,
                    SessionMode::ReadOnly,
                    Authentication::User(Pin::Value(&pin)),
                )
                .unwrap();
            let encoded = session
                .encrypt_aes_gcm_envelope(
                    &key,
                    &mut state,
                    b"interop",
                    b"public synthetic plaintext",
                )
                .unwrap();
            session.close().unwrap();
            provider.finalize().unwrap();
            let envelope = AesGcmEnvelope::parse(&encoded).unwrap();
            assert_eq!(envelope.nonce()[11], writer as u8);
            for reader in &paths {
                let provider = Provider::load(reader).unwrap();
                let mut session = provider
                    .management(
                        &token,
                        SessionMode::ReadOnly,
                        Authentication::User(Pin::Value(&pin)),
                    )
                    .unwrap();
                assert_eq!(
                    session
                        .decrypt_aes_gcm_envelope(&key, b"interop", &encoded)
                        .unwrap()
                        .expose_secret(),
                    b"public synthetic plaintext"
                );
                assert_eq!(
                    session
                        .decrypt_aes_gcm(
                            &key,
                            &AesGcmDecryptRequest {
                                nonce: envelope.nonce(),
                                aad: b"interop",
                                ciphertext: envelope.ciphertext()
                            }
                        )
                        .unwrap()
                        .expose_secret(),
                    b"public synthetic plaintext"
                );
                session.close().unwrap();
                provider.finalize().unwrap();
            }
        }
    }
}
