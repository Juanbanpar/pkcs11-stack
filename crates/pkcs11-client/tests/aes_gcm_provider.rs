// SPDX-License-Identifier: MIT OR Apache-2.0
//! Generated AES keys and authenticated-decryption failures through the client API.
use pkcs11_client::{
    AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmOperation, AesGcmStreamParameters,
    AesKeyPurpose, AesKeyRequest, AesKeySize, Authentication, ErrorKind, ObjectRef, Pin, Provider,
    SessionMode,
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
        struct Chunks<'a> {
            bytes: std::io::Cursor<&'a [u8]>,
            maximum: usize,
            interrupted: bool,
        }
        impl std::io::Read for Chunks<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                self.maximum = self.maximum.max(out.len());
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let length = out.len().min(3071);
                std::io::Read::read(&mut self.bytes, &mut out[..length])
            }
        }
        let large: Vec<u8> = (0..1_000_003).map(|i| (i % 251) as u8).collect();
        for (case, input) in [&[][..], encrypt.plaintext, &large].into_iter().enumerate() {
            let nonce = [0x82 + index as u8 + case as u8; 12];
            let parameters = AesGcmStreamParameters {
                nonce: &nonce,
                aad: b"reader context",
                maximum_plaintext: input.len(),
            };
            let mut reader = Chunks {
                bytes: std::io::Cursor::new(input),
                maximum: 0,
                interrupted: false,
            };
            let ciphertext = session
                .encrypt_aes_gcm_reader(&key, parameters, &mut reader)
                .unwrap();
            assert_eq!(reader.maximum, 65536);
            let expected = session
                .encrypt_aes_gcm(
                    &key,
                    &AesGcmEncryptRequest {
                        nonce: &nonce,
                        aad: parameters.aad,
                        plaintext: input,
                    },
                )
                .unwrap();
            assert_eq!(ciphertext, expected);
            let mut reader = Chunks {
                bytes: std::io::Cursor::new(&ciphertext),
                maximum: 0,
                interrupted: false,
            };
            let output = session
                .decrypt_aes_gcm_reader(&key, parameters, &mut reader)
                .unwrap();
            assert_eq!(output.expose_secret(), input);
            assert_eq!(reader.maximum, 65536);
            assert!(!format!("{output:?} {parameters:?}").contains("canary"));
            session.state().unwrap();
        }
        session.state().unwrap();
        session.close().unwrap();
        let mut corrupted = ciphertext;
        *corrupted.last_mut().unwrap() ^= 1;
        let mut session = provider
            .management(&token, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        let parameters = AesGcmStreamParameters {
            nonce: encrypt.nonce,
            aad: encrypt.aad,
            maximum_plaintext: encrypt.plaintext.len(),
        };
        let error = session
            .decrypt_aes_gcm_reader(&key, parameters, &mut std::io::Cursor::new(&corrupted))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Runtime);
        assert!(session.state().is_err());
        session.close().unwrap();
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
