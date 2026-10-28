// SPDX-License-Identifier: MIT OR Apache-2.0
//! NIST known answers, tampering, policy and generated-key use on disposable SoftHSM.
#[path = "fixtures/aes_gcm_vectors.rs"]
mod vectors;
use cryptoki::object::KeyType;
use pkcs11_runtime::{
    AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmOperation, AesGcmStreamParameters,
    AesKeyPurpose, AesKeyRequest, AesKeySize, Attribute, Authentication, Error, MechanismType,
    Module, ObjectClass, ObjectRef, Pin, SessionMode,
};
use secrecy::{ExposeSecret, SecretString};
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn reference(token: &str, id: &str, kind: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token={token};object={id};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn template(id: &str, key: &[u8]) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Label(id.as_bytes().to_vec()),
        Attribute::Id(id.as_bytes().to_vec()),
        Attribute::Value(key.to_vec()),
    ]
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn nist_vectors_tampering_policy_and_generated_keys() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let module = Module::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let name = "client-test";
    let token = module
        .resolve_token_uri(&format!("pkcs11:token={name}").parse().unwrap())
        .unwrap();
    let pin = SecretString::from("12345678");
    let mut setup = token.open_session(SessionMode::ReadWrite).unwrap();
    setup
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, v) in vectors::VECTORS.iter().enumerate() {
        setup
            .create_object(&template(&format!("gcm-vector-{index}"), &hex(v.key)))
            .unwrap();
    }
    for (index, v) in vectors::VECTORS.iter().enumerate() {
        let key = reference(name, &format!("gcm-vector-{index}"), "secret-key");
        let nonce: [u8; 12] = hex(v.nonce).try_into().unwrap();
        let aad = hex(v.aad);
        let plaintext = hex(v.plaintext);
        let ciphertext = hex(v.ciphertext);
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let caps = session
            .aes_gcm_capabilities(&key, AesGcmOperation::Encrypt)
            .unwrap();
        assert_eq!(caps.key_size.length(), v.key.len() / 2);
        let request = AesGcmEncryptRequest {
            nonce: &nonce,
            aad: &aad,
            plaintext: &plaintext,
        };
        assert_eq!(
            session.encrypt_aes_gcm(&key, &request).unwrap(),
            ciphertext,
            "vector {index}"
        );
        let request = AesGcmDecryptRequest {
            nonce: &nonce,
            aad: &aad,
            ciphertext: &ciphertext,
        };
        let output = session.decrypt_aes_gcm(&key, &request).unwrap();
        assert_eq!(output.expose_secret(), &plaintext);
        assert!(!format!("{output:?}").contains("canary"));
        let parameters = AesGcmStreamParameters {
            nonce: &nonce,
            aad: &aad,
            maximum_plaintext: plaintext.len(),
        };
        for operation in [AesGcmOperation::Encrypt, AesGcmOperation::Decrypt] {
            assert_eq!(
                session
                    .aes_gcm_streaming_capabilities(&key, operation)
                    .unwrap()
                    .key_size
                    .length(),
                v.key.len() / 2
            );
        }
        for size in [1, 15, 16, 17, 65536] {
            let mut operation = session.start_aes_gcm_encryption(&key, parameters).unwrap();
            let mut encrypted = operation.update(&[]).unwrap();
            for chunk in plaintext.chunks(size) {
                encrypted.extend(operation.update(chunk).unwrap());
            }
            encrypted.extend(operation.finish().unwrap());
            assert_eq!(
                encrypted, ciphertext,
                "multipart vector {index}, chunk {size}"
            );
            let mut operation = session.start_aes_gcm_decryption(&key, parameters).unwrap();
            operation.update(&[]).unwrap();
            for chunk in ciphertext.chunks(size) {
                operation.update(chunk).unwrap();
            }
            assert_eq!(operation.finish().unwrap().expose_secret(), &plaintext);
            session.info().unwrap();
        }
        // Short inputs fail validation without making the session unusable.
        assert!(matches!(
            session.decrypt_aes_gcm(
                &key,
                &AesGcmDecryptRequest {
                    ciphertext: &[0; 15],
                    ..request
                }
            ),
            Err(Error::InvalidParameters(_))
        ));
        session.info().unwrap();
        session.close().unwrap();
        // Each provider failure is checked in a new session: failed sessions cannot retry.
        for mutation in 0..5 {
            if mutation >= 3 && plaintext.is_empty() {
                continue;
            }
            let mut nonce = nonce;
            let mut aad = aad.clone();
            let mut ciphertext = ciphertext.clone();
            match mutation {
                0 => nonce[0] ^= 1,
                1 => aad.push(1),
                2 => *ciphertext.last_mut().unwrap() ^= 1,
                3 => ciphertext[0] ^= 1,
                _ => {
                    ciphertext.pop();
                }
            }
            let mut stream_session = token.open_session(SessionMode::ReadOnly).unwrap();
            let mut operation = stream_session
                .start_aes_gcm_decryption(
                    &key,
                    AesGcmStreamParameters {
                        nonce: &nonce,
                        aad: &aad,
                        maximum_plaintext: plaintext.len(),
                    },
                )
                .unwrap();
            for chunk in ciphertext.chunks(3) {
                operation.update(chunk).unwrap();
            }
            assert!(operation.finish().is_err());
            assert!(stream_session.info().is_err());
            stream_session.close().unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let result = session.decrypt_aes_gcm(
                &key,
                &AesGcmDecryptRequest {
                    nonce: &nonce,
                    aad: &aad,
                    ciphertext: &ciphertext,
                },
            );
            assert!(
                matches!(
                    result,
                    Err(Error::Backend {
                        operation: "AES GCM decrypt",
                        ..
                    })
                ),
                "vector {index}, mutation {mutation}"
            );
            assert!(matches!(session.info(), Err(Error::Closed)));
            session.close().unwrap();
        }
    }
    // Direction permissions and allowed mechanisms are rechecked before each crypto call.
    let id = "gcm-policy";
    setup.create_object(&template(id, &[0x42; 16])).unwrap();
    let key = reference(name, id, "secret-key");
    setup
        .resolve(&key)
        .unwrap()
        .update_attributes(&[Attribute::Encrypt(false)])
        .unwrap();
    assert!(matches!(
        setup.encrypt_aes_gcm(
            &key,
            &AesGcmEncryptRequest {
                nonce: &[1; 12],
                aad: &[],
                plaintext: b"canary"
            }
        ),
        Err(Error::UnsupportedAesGcm)
    ));
    setup
        .aes_gcm_capabilities(&key, AesGcmOperation::Decrypt)
        .unwrap();
    setup
        .resolve(&key)
        .unwrap()
        .update_attributes(&[Attribute::Encrypt(true), Attribute::Decrypt(false)])
        .unwrap();
    assert!(matches!(
        setup.aes_gcm_capabilities(&key, AesGcmOperation::Decrypt),
        Err(Error::UnsupportedAesGcm)
    ));
    let mut restricted = template("gcm-restricted", &[0x43; 16]);
    restricted.push(Attribute::AllowedMechanisms(vec![MechanismType::AES_ECB]));
    setup.create_object(&restricted).unwrap();
    assert!(matches!(
        setup.aes_gcm_capabilities(
            &reference(name, "gcm-restricted", "secret-key"),
            AesGcmOperation::Encrypt
        ),
        Err(Error::UnsupportedAesGcm)
    ));
    setup.info().unwrap();
    // A mechanism outside cryptoki's named execution variants must survive metadata decoding.
    let cmac_general = MechanismType::try_from(0x0000_108b).unwrap();
    for (id, allowed, permitted) in [
        (
            "gcm-mixed-mechanisms",
            vec![MechanismType::AES_GCM, cmac_general],
            true,
        ),
        ("gcm-cmac-only", vec![cmac_general], false),
    ] {
        let mut attributes = template(id, &[0x44; 16]);
        attributes.push(Attribute::AllowedMechanisms(allowed.clone()));
        setup.create_object(&attributes).unwrap();
        let key = reference(name, id, "secret-key");
        let metadata = setup
            .resolve(&key)
            .unwrap()
            .read_attributes(&[pkcs11_runtime::AttributeType::AllowedMechanisms])
            .unwrap();
        assert_eq!(
            metadata.expose_values(),
            &[Attribute::AllowedMechanisms(allowed)]
        );
        let result = setup.encrypt_aes_gcm(
            &key,
            &AesGcmEncryptRequest {
                nonce: &[3; 12],
                aad: b"mixed mechanisms",
                plaintext: b"GCM remains permitted",
            },
        );
        if permitted {
            let ciphertext = result.unwrap();
            let plaintext = setup
                .decrypt_aes_gcm(
                    &key,
                    &AesGcmDecryptRequest {
                        nonce: &[3; 12],
                        aad: b"mixed mechanisms",
                        ciphertext: &ciphertext,
                    },
                )
                .unwrap();
            assert_eq!(plaintext.expose_secret(), b"GCM remains permitted");
        } else {
            assert!(matches!(result, Err(Error::UnsupportedAesGcm)));
        }
        setup.info().unwrap();
    }
    let mut generic = template("gcm-wrong-type", &[0x42; 16]);
    generic[1] = Attribute::KeyType(KeyType::GENERIC_SECRET);
    setup.create_object(&generic).unwrap();
    assert!(matches!(
        setup.aes_gcm_capabilities(
            &reference(name, "gcm-wrong-type", "secret-key"),
            AesGcmOperation::Encrypt
        ),
        Err(Error::UnsupportedAesGcm)
    ));
    setup
        .create_object(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Token(true),
            Attribute::Label(b"gcm-data".to_vec()),
            Attribute::Value(vec![]),
        ])
        .unwrap();
    assert!(matches!(
        setup.aes_gcm_capabilities(
            &reference(name, "gcm-data", "data"),
            AesGcmOperation::Encrypt
        ),
        Err(Error::UnsupportedAesGcm)
    ));
    for (index, size) in [
        AesKeySize::Bits128,
        AesKeySize::Bits192,
        AesKeySize::Bits256,
    ]
    .into_iter()
    .enumerate()
    {
        let label = format!("gcm-generated-{index}");
        setup
            .generate_aes_key(&AesKeyRequest {
                size,
                purpose: AesKeyPurpose::Encryption,
                id: label.as_bytes(),
                label: label.as_bytes(),
            })
            .unwrap();
        let key = reference(name, &label, "secret-key");
        let ciphertext = setup
            .encrypt_aes_gcm(
                &key,
                &AesGcmEncryptRequest {
                    nonce: &[2; 12],
                    aad: b"context",
                    plaintext: b"generated-key-canary",
                },
            )
            .unwrap();
        let plaintext = setup
            .decrypt_aes_gcm(
                &key,
                &AesGcmDecryptRequest {
                    nonce: &[2; 12],
                    aad: b"context",
                    ciphertext: &ciphertext,
                },
            )
            .unwrap();
        assert_eq!(plaintext.expose_secret(), b"generated-key-canary");
        assert!(!format!("{plaintext:?}").contains("canary"));
        let label = format!("gcm-wrapper-{index}");
        setup
            .generate_aes_key(&AesKeyRequest {
                size,
                purpose: AesKeyPurpose::Wrapping,
                id: label.as_bytes(),
                label: label.as_bytes(),
            })
            .unwrap();
        let key = reference(name, &label, "secret-key");
        for op in [AesGcmOperation::Encrypt, AesGcmOperation::Decrypt] {
            assert!(matches!(
                setup.aes_gcm_capabilities(&key, op),
                Err(Error::UnsupportedAesGcm)
            ));
        }
    }
    setup.close().unwrap();
    module.finalize().unwrap();
}
