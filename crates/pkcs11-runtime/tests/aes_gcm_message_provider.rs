// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real NSS message API probe against independent NIST known answers.
#[path = "fixtures/aes_gcm_vectors.rs"]
mod vectors;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Function, Pkcs11},
    mechanism::{
        Mechanism, MechanismType, MessageParam,
        aead::{GcmMessageParams, GeneratorFunction},
    },
    object::{Attribute, KeyType, ObjectClass},
};
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
#[test]
#[ignore = "requires tools/test-nss.sh disposable database"]
fn nss_native_message_probe() {
    assert_eq!(
        std::env::var("PKCS11_TEST_NSS_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = Pkcs11::new(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    assert!(module.interface().version.major() >= 3);
    for f in [
        Function::MessageEncryptInit,
        Function::EncryptMessage,
        Function::MessageEncryptFinal,
        Function::MessageDecryptInit,
        Function::DecryptMessage,
        Function::MessageDecryptFinal,
    ] {
        assert!(module.is_fn_supported(f));
    }
    let slot = module
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| module.get_token_info(*s).unwrap().label() == "kdf-test")
        .unwrap();
    let info = module
        .get_mechanism_info(slot, MechanismType::AES_GCM)
        .unwrap();
    assert!(info.message_encrypt() && info.message_decrypt());
    let session = module.open_rw_session(slot).unwrap();
    for v in vectors::VECTORS {
        let key = session
            .create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Value(hex(v.key)),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
            ])
            .unwrap();
        let original = hex(v.nonce);
        let aad = hex(v.aad);
        let plaintext = hex(v.plaintext);
        let expected = hex(v.ciphertext);
        let mut nonce = original.clone();
        let mut tag = [0; 16];
        session
            .message_encrypt_init(&Mechanism::AesGcmMessageInit, key)
            .unwrap();
        let mut ciphertext = vec![0; plaintext.len()];
        let mut params = MessageParam::AesGcmMessage(
            GcmMessageParams::new(
                &mut nonce,
                0.into(),
                GeneratorFunction::NoGenerate,
                &mut tag,
            )
            .unwrap(),
        );
        assert_eq!(
            session
                .encrypt_message_into(&mut params, &aad, &plaintext, &mut ciphertext)
                .unwrap(),
            plaintext.len()
        );
        assert_eq!(nonce, original);
        ciphertext.extend(tag);
        assert_eq!(ciphertext, expected);
        session.message_encrypt_final().unwrap();
        session
            .message_decrypt_init(&Mechanism::AesGcmMessageInit, key)
            .unwrap();
        let mut params = MessageParam::AesGcmMessage(
            GcmMessageParams::new(
                &mut nonce,
                0.into(),
                GeneratorFunction::NoGenerate,
                &mut tag,
            )
            .unwrap(),
        );
        let mut decrypted = vec![0; plaintext.len()];
        assert_eq!(
            session
                .decrypt_message_into(
                    &mut params,
                    &aad,
                    &ciphertext[..ciphertext.len() - 16],
                    &mut decrypted
                )
                .unwrap(),
            plaintext.len()
        );
        assert_eq!(decrypted, plaintext);
        session.message_decrypt_final().unwrap();
        session.destroy_object(key).unwrap();
    }
    session.close().unwrap();
    module.finalize().unwrap();
}

#[test]
#[ignore = "requires tools/test-nss.sh disposable database"]
fn nss_runtime_messages_vectors_tampering_and_generated_keys() {
    use pkcs11_runtime::{
        AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmOperation, AesKeyPurpose, AesKeyRequest,
        AesKeySize, Authentication, Error, Module, ObjectRef, Pin, SessionMode,
    };
    use secrecy::{ExposeSecret, SecretString};
    assert_eq!(
        std::env::var("PKCS11_TEST_NSS_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let mut setup = token.open_session(SessionMode::ReadWrite).unwrap();
    let pin = SecretString::from("12345678");
    setup
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, v) in vectors::VECTORS.iter().enumerate() {
        let label = format!("gcm-message-vector-{index}");
        setup
            .create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Value(hex(v.key)),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Id(label.as_bytes().to_vec()),
            ])
            .unwrap();
        let key = ObjectRef::new(
            format!("pkcs11:token=kdf-test;object={label};type=secret-key")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let nonce: [u8; 12] = hex(v.nonce).try_into().unwrap();
        let aad = hex(v.aad);
        let plaintext = hex(v.plaintext);
        let expected = hex(v.ciphertext);
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        assert_eq!(
            session
                .aes_gcm_message_capabilities(&key, AesGcmOperation::Encrypt)
                .unwrap()
                .key_size
                .length(),
            v.key.len() / 2
        );
        let mut encrypt = session.start_aes_gcm_message_encryption(&key).unwrap();
        let mut messages = vec![];
        for index in 0..3 {
            let mut nonce = nonce;
            nonce[0] ^= index;
            let ciphertext = encrypt
                .encrypt(&AesGcmEncryptRequest {
                    nonce: &nonce,
                    aad: &aad,
                    plaintext: &plaintext,
                })
                .unwrap();
            if index == 0 {
                assert_eq!(ciphertext, expected);
            }
            messages.push((nonce, ciphertext));
        }
        encrypt.finish().unwrap();
        let mut decrypt = session.start_aes_gcm_message_decryption(&key).unwrap();
        for (nonce, ciphertext) in &messages {
            assert_eq!(
                decrypt
                    .decrypt(&AesGcmDecryptRequest {
                        nonce,
                        aad: &aad,
                        ciphertext
                    })
                    .unwrap()
                    .expose_secret(),
                &plaintext
            );
        }
        decrypt.finish().unwrap();
        session.info().unwrap();
        session.close().unwrap();
        for mutation in 0..4 {
            if mutation == 3 && plaintext.is_empty() {
                continue;
            }
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let mut nonce = nonce;
            let mut aad = aad.clone();
            let mut ciphertext = expected.clone();
            match mutation {
                0 => nonce[0] ^= 1,
                1 => aad.push(1),
                2 => *ciphertext.last_mut().unwrap() ^= 1,
                _ => ciphertext[0] ^= 1,
            }
            let mut decrypt = session.start_aes_gcm_message_decryption(&key).unwrap();
            let request = AesGcmDecryptRequest {
                nonce: &nonce,
                aad: &aad,
                ciphertext: &ciphertext,
            };
            assert!(decrypt.decrypt(&request).is_err());
            assert!(matches!(decrypt.decrypt(&request), Err(Error::Closed)));
            assert!(matches!(decrypt.finish(), Err(Error::Closed)));
            assert!(matches!(session.info(), Err(Error::Closed)));
            session.close().unwrap();
        }
    }
    for (index, size) in [
        AesKeySize::Bits128,
        AesKeySize::Bits192,
        AesKeySize::Bits256,
    ]
    .into_iter()
    .enumerate()
    {
        let label = format!("gcm-message-generated-{index}");
        setup
            .generate_aes_key(&AesKeyRequest {
                size,
                purpose: AesKeyPurpose::Encryption,
                id: label.as_bytes(),
                label: label.as_bytes(),
            })
            .unwrap();
        let key = ObjectRef::new(
            format!("pkcs11:token=kdf-test;object={label};type=secret-key")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let mut process = setup.start_aes_gcm_message_encryption(&key).unwrap();
        let ciphertext = process
            .encrypt(&AesGcmEncryptRequest {
                nonce: &[0x42; 12],
                aad: b"binary\0\xff",
                plaintext: b"generated message canary",
            })
            .unwrap();
        process.finish().unwrap();
        std::fs::write(
            std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap())
                .join(format!("{label}.ciphertext")),
            &ciphertext,
        )
        .unwrap();
        let mut process = setup.start_aes_gcm_message_decryption(&key).unwrap();
        assert_eq!(
            process
                .decrypt(&AesGcmDecryptRequest {
                    nonce: &[0x42; 12],
                    aad: b"binary\0\xff",
                    ciphertext: &ciphertext
                })
                .unwrap()
                .expose_secret(),
            b"generated message canary"
        );
        process.finish().unwrap();
    }
    // Exercise exact public allocation limits on a protected token-generated key.
    let key = ObjectRef::new(
        "pkcs11:token=kdf-test;object=gcm-message-generated-2;type=secret-key"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let plaintext = vec![0x5a; pkcs11_runtime::AES_GCM_MAXIMUM_PLAINTEXT];
    let aad = vec![0xa6; pkcs11_runtime::AES_GCM_MAXIMUM_AAD];
    let mut process = setup.start_aes_gcm_message_encryption(&key).unwrap();
    let ciphertext = process
        .encrypt(&AesGcmEncryptRequest {
            nonce: &[0x43; 12],
            aad: &aad,
            plaintext: &plaintext,
        })
        .unwrap();
    process.finish().unwrap();
    let mut process = setup.start_aes_gcm_message_decryption(&key).unwrap();
    assert_eq!(
        process
            .decrypt(&AesGcmDecryptRequest {
                nonce: &[0x43; 12],
                aad: &aad,
                ciphertext: &ciphertext
            })
            .unwrap()
            .expose_secret(),
        &plaintext
    );
    process.finish().unwrap();
    setup.close().unwrap();
    module.finalize().unwrap();
}
