// SPDX-License-Identifier: MIT OR Apache-2.0
//! Generated AES keys and authenticated-decryption failures through the client API.
use pkcs11_client::{
    AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmOperation, AesKeyPurpose, AesKeyRequest,
    AesKeySize, Authentication, ErrorKind, ObjectRef, Pin, Provider, SessionMode,
};
use secrecy::{ExposeSecret, SecretString};
#[test]
#[ignore = "requires tools/test-softhsm.sh or tools/test-kem-hkdf.sh disposable store"]
fn typed_aes_gcm_permissions_redaction_and_failed_session_cleanup() {
    let (path, name) = if std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref() == Ok("1") {
        (
            std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap(),
            "kdf-test",
        )
    } else {
        assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
        (
            std::env::var_os("PKCS11_TEST_MODULE").unwrap(),
            "client-test",
        )
    };
    let provider = Provider::load(path).unwrap();
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
