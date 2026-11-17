// SPDX-License-Identifier: MIT OR Apache-2.0
//! Generated AES keys and authenticated-decryption failures through the client API.
use pkcs11_client::{
    AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmOperation, AesKeyPurpose, AesKeyRequest,
    AesKeySize, Authentication, ErrorKind, ObjectRef, Pin, Provider, SessionMode,
};
use secrecy::{ExposeSecret, SecretString};
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn typed_aes_gcm_permissions_redaction_and_failed_session_cleanup() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let name = "client-test";
    let token = format!("pkcs11:token={name}").parse().unwrap();
    let pin = SecretString::from("12345678");
    let auth = || Authentication::User(Pin::Value(&pin));
    let reference = |label: &str| {
        ObjectRef::new(
            format!("pkcs11:token={name};object={label};type=secret-key")
                .parse()
                .unwrap(),
        )
        .unwrap()
    };
    // This live RW anchor retains token-wide USER login for the read-only sessions.
    let mut setup = provider
        .management(&token, SessionMode::ReadWrite, auth())
        .unwrap();
    for (index, size) in [
        AesKeySize::Bits128,
        AesKeySize::Bits192,
        AesKeySize::Bits256,
    ]
    .into_iter()
    .enumerate()
    {
        let label = format!("client-gcm-{index}");
        setup
            .generate_aes_key(&AesKeyRequest {
                size,
                purpose: AesKeyPurpose::Encryption,
                id: label.as_bytes(),
                label: label.as_bytes(),
            })
            .unwrap();
        let key = reference(&label);
        let mut session = provider
            .management(&token, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        for operation in [AesGcmOperation::Encrypt, AesGcmOperation::Decrypt] {
            assert_eq!(
                session
                    .aes_gcm_capabilities(&key, operation)
                    .unwrap()
                    .key_size,
                size
            );
        }
        let encrypt = AesGcmEncryptRequest {
            nonce: &[0x72; 12],
            aad: b"client context",
            plaintext: b"client-plaintext-canary",
        };
        let ciphertext = session.encrypt_aes_gcm(&key, &encrypt).unwrap();
        let decrypt = AesGcmDecryptRequest {
            nonce: encrypt.nonce,
            aad: encrypt.aad,
            ciphertext: &ciphertext,
        };
        let plaintext = session.decrypt_aes_gcm(&key, &decrypt).unwrap();
        assert_eq!(plaintext.expose_secret(), encrypt.plaintext);
        assert!(!format!("{plaintext:?} {encrypt:?} {decrypt:?}").contains("canary"));
        assert!(session.export_public(&key).is_err());
        assert_eq!(
            session
                .decrypt_aes_gcm(
                    &key,
                    &AesGcmDecryptRequest {
                        ciphertext: &[],
                        ..decrypt
                    }
                )
                .unwrap_err()
                .kind(),
            ErrorKind::Input
        );
        session.state().unwrap();
        session.close().unwrap();
        let mut corrupted = ciphertext;
        *corrupted.last_mut().unwrap() ^= 1;
        let mut session = provider
            .management(&token, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        let error = session
            .decrypt_aes_gcm(
                &key,
                &AesGcmDecryptRequest {
                    nonce: encrypt.nonce,
                    aad: encrypt.aad,
                    ciphertext: &corrupted,
                },
            )
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Runtime);
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert!(session.state().is_err());
        session.close().unwrap();
        let label = format!("client-gcm-wrapper-{index}");
        setup
            .generate_aes_key(&AesKeyRequest {
                size,
                purpose: AesKeyPurpose::Wrapping,
                id: label.as_bytes(),
                label: label.as_bytes(),
            })
            .unwrap();
        assert_eq!(
            setup
                .aes_gcm_capabilities(&reference(&label), AesGcmOperation::Encrypt)
                .unwrap_err()
                .kind(),
            ErrorKind::Policy
        );
    }
    setup.close().unwrap();
    provider.finalize().unwrap();
}

#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn managed_envelopes_authenticate_boundaries_and_consume_failed_reservations() {
    use pkcs11_client::{
        AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_PLAINTEXT, AesGcmEnvelope, NonceSequence,
    };
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=client-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let mut setup = provider
        .management(
            &token,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    let root = std::path::PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    for (index, size) in [
        AesKeySize::Bits128,
        AesKeySize::Bits192,
        AesKeySize::Bits256,
    ]
    .into_iter()
    .enumerate()
    {
        let label = format!("envelope-{index}");
        setup
            .generate_aes_key(&AesKeyRequest {
                size,
                purpose: AesKeyPurpose::Encryption,
                id: label.as_bytes(),
                label: label.as_bytes(),
            })
            .unwrap();
        let key = ObjectRef::new(
            format!("pkcs11:token=client-test;object={label};type=secret-key")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let path = root.join(&label);
        let mut state = NonceSequence::create(&path, &key).unwrap();
        for (plaintext, aad) in [
            (Vec::new(), Vec::new()),
            (
                vec![0x55; AES_GCM_MAXIMUM_PLAINTEXT],
                vec![0xAA; AES_GCM_MAXIMUM_AAD],
            ),
        ] {
            let mut session = provider
                .management(&token, SessionMode::ReadOnly, Authentication::None)
                .unwrap();
            let encoded = session
                .encrypt_aes_gcm_envelope(&key, &mut state, &aad, &plaintext)
                .unwrap();
            assert_eq!(
                session
                    .decrypt_aes_gcm_envelope(&key, &aad, &encoded)
                    .unwrap()
                    .expose_secret(),
                &plaintext
            );
            session.close().unwrap();
            for offset in [7, 19, encoded.len() - 1] {
                let mut damaged = encoded.clone();
                damaged[offset] ^= 1;
                let mut session = provider
                    .management(&token, SessionMode::ReadOnly, Authentication::None)
                    .unwrap();
                assert!(
                    session
                        .decrypt_aes_gcm_envelope(&key, &aad, &damaged)
                        .is_err()
                );
                assert!(session.state().is_err());
                session.close().unwrap();
            }
            let mut session = provider
                .management(&token, SessionMode::ReadOnly, Authentication::None)
                .unwrap();
            let mut wrong_aad = aad.clone();
            if wrong_aad.is_empty() {
                wrong_aad.push(1);
            } else {
                wrong_aad[0] ^= 1;
            }
            assert!(
                session
                    .decrypt_aes_gcm_envelope(&key, &wrong_aad, &encoded)
                    .is_err()
            );
            assert!(session.state().is_err());
            session.close().unwrap();
            let mut bad_header = encoded.clone();
            bad_header[6] = 2;
            let mut session = provider
                .management(&token, SessionMode::ReadOnly, Authentication::None)
                .unwrap();
            assert!(
                session
                    .decrypt_aes_gcm_envelope(&key, &aad, &bad_header)
                    .is_err()
            );
            session.state().unwrap();
            session.close().unwrap();
            assert!(AesGcmEnvelope::parse(&encoded).is_ok());
        }
        // A policy rejection after reservation still burns its nonce; never retry it.
        let used = state.reserve(&key).unwrap();
        let mut session = provider
            .management(&token, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        let damaged = [b"P11GCM\x01".as_slice(), &[0; 12], &[0; 16]].concat();
        assert!(
            session
                .decrypt_aes_gcm_envelope(&key, &[], &damaged)
                .is_err()
        );
        // An invalidated session cannot encrypt, but allocator state advances first.
        assert!(
            session
                .encrypt_aes_gcm_envelope(&key, &mut state, &[], b"attempt")
                .is_err()
        );
        session.close().unwrap();
        drop(state);
        let after = NonceSequence::open(&path, &key)
            .unwrap()
            .reserve(&key)
            .unwrap();
        assert_eq!(after[11], used[11] + 2);
    }
    setup.close().unwrap();
    provider.finalize().unwrap();
}
