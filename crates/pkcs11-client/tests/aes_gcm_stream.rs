// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reader budgets, plaintext withholding, redaction and exclusive init-only borrows.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/aes_gcm_stream_module.rs"]
mod fixture;
use fixture::AesGcmStreamModule;
use pkcs11_client::*;
use secrecy::ExposeSecret;
use std::io::{self, Read};
struct Input {
    bytes: io::Cursor<Vec<u8>>,
    maximum: usize,
    interrupted: bool,
    fail: bool,
    panic: bool,
}
impl Input {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: io::Cursor::new(bytes.to_vec()),
            maximum: 0,
            interrupted: false,
            fail: false,
            panic: false,
        }
    }
}
impl Read for Input {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.maximum = self.maximum.max(out.len());
        assert!(!self.panic, "reader panic canary");
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.bytes.position() == self.bytes.get_ref().len() as u64 && self.fail {
            return Err(io::Error::other("reader error canary"));
        }
        self.bytes.read(&mut out[..1])
    }
}
fn key() -> ObjectRef {
    ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap()
}
fn parameters() -> AesGcmStreamParameters<'static> {
    AesGcmStreamParameters {
        nonce: &[0xA5; 12],
        aad: &[],
        maximum_plaintext: 3,
    }
}
fn ciphertext(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| b ^ 0x80).chain([0xEF; 16]).collect()
}
fn with_fixture(fault: u8, aad_length: usize, test: impl FnOnce(&mut ManagementSession<'_>)) {
    let fixture = AesGcmStreamModule::new(3, 2, fault, 16, aad_length);
    let provider = Provider::load(fixture.path()).unwrap();
    let mut session = provider
        .management(
            &"pkcs11:token=cmac".parse().unwrap(),
            SessionMode::ReadOnly,
            Authentication::None,
        )
        .unwrap();
    test(&mut session);
    session.close().unwrap();
    provider.finalize().unwrap();
}
#[test]
fn bounded_empty_interrupted_readers_and_authenticated_results() {
    for fault in [0, 24] {
        with_fixture(fault, 0, |session| {
            for operation in [AesGcmOperation::Encrypt, AesGcmOperation::Decrypt] {
                assert_eq!(
                    session
                        .aes_gcm_streaming_capabilities(&key(), operation)
                        .unwrap()
                        .key_size,
                    AesKeySize::Bits128
                );
            }
            for message in [&[][..], b"abc"] {
                let mut input = Input::new(message);
                let encrypted = session
                    .encrypt_aes_gcm_reader(&key(), parameters(), &mut input)
                    .unwrap();
                assert_eq!(encrypted, ciphertext(message));
                assert_eq!(input.maximum, 65536);
                let mut input = Input::new(&encrypted);
                let plaintext = session
                    .decrypt_aes_gcm_reader(&key(), parameters(), &mut input)
                    .unwrap();
                assert_eq!(plaintext.expose_secret(), message);
                assert_eq!(input.maximum, 65536);
                assert!(!format!("{plaintext:?}").contains("abc"));
                session.state().unwrap();
            }
            let mut operation = session
                .start_aes_gcm_encryption(&key(), parameters())
                .unwrap();
            assert_eq!(operation.capabilities().key_size, AesKeySize::Bits128);
            operation.update(b"a").unwrap();
            operation.cancel().unwrap();
            let mut operation = session
                .start_aes_gcm_decryption(&key(), parameters())
                .unwrap();
            assert_eq!(operation.capabilities().key_size, AesKeySize::Bits128);
            operation.update(&[0xEF]).unwrap();
            operation.cancel().unwrap();
            session.state().unwrap();
        });
    }
}
#[test]
fn parameter_borrows_end_at_init_and_preflight_does_not_read() {
    with_fixture(0, 3, |session| {
        let mut operation = {
            let nonce = [0xA5; 12];
            let aad = vec![0xA6; 3];
            session
                .start_aes_gcm_encryption(
                    &key(),
                    AesGcmStreamParameters {
                        nonce: &nonce,
                        aad: &aad,
                        ..parameters()
                    },
                )
                .unwrap()
        };
        let mut encrypted = operation.update(b"abc").unwrap();
        encrypted.extend(operation.finish().unwrap());
        let mut operation = {
            let nonce = [0xA5; 12];
            let aad = vec![0xA6; 3];
            session
                .start_aes_gcm_decryption(
                    &key(),
                    AesGcmStreamParameters {
                        nonce: &nonce,
                        aad: &aad,
                        ..parameters()
                    },
                )
                .unwrap()
        };
        operation.update(&encrypted).unwrap();
        assert_eq!(operation.finish().unwrap().expose_secret(), b"abc");
        assert!(
            !format!(
                "{:?}",
                AesGcmStreamParameters {
                    aad: b"aad canary",
                    ..parameters()
                }
            )
            .contains("canary")
        );
        let mut input = Input::new(b"abc");
        for invalid in [
            AesGcmStreamParameters {
                maximum_plaintext: usize::MAX,
                ..parameters()
            },
            AesGcmStreamParameters {
                aad: &[0; AES_GCM_MAXIMUM_AAD + 1],
                ..parameters()
            },
        ] {
            assert!(
                session
                    .encrypt_aes_gcm_reader(&key(), invalid, &mut input)
                    .is_err()
            );
            assert!(
                session
                    .decrypt_aes_gcm_reader(&key(), invalid, &mut input)
                    .is_err()
            );
        }
        assert_eq!(input.maximum, 0);
        session.state().unwrap();
    });
    for fault in [10, 11, 12, 13, 14, 15] {
        with_fixture(fault, 0, |session| {
            let mut input = Input::new(b"abc");
            if fault <= 12 {
                assert!(
                    session
                        .encrypt_aes_gcm_reader(&key(), parameters(), &mut input)
                        .is_err()
                );
            } else {
                assert!(
                    session
                        .decrypt_aes_gcm_reader(&key(), parameters(), &mut input)
                        .is_err()
                );
            }
            assert_eq!(input.maximum, 0);
            session.state().unwrap();
        });
    }
}
#[test]
fn read_native_and_authentication_failures_return_no_plaintext_and_discard() {
    for encrypt in [true, false] {
        for fault in [0, 17, 18, 19, 20, 21, 22, 23, 26, 27, 36, 38] {
            if encrypt && matches!(fault, 36 | 38) {
                continue;
            }
            with_fixture(fault, 0, |session| {
                let data = if encrypt {
                    b"abc".to_vec()
                } else {
                    ciphertext(b"abc")
                };
                let mut input = Input {
                    fail: fault == 0,
                    ..Input::new(&data)
                };
                let error = if encrypt {
                    session
                        .encrypt_aes_gcm_reader(&key(), parameters(), &mut input)
                        .unwrap_err()
                } else {
                    session
                        .decrypt_aes_gcm_reader(&key(), parameters(), &mut input)
                        .unwrap_err()
                };
                if fault == 0 {
                    assert!(matches!(error, Error::CipherInput));
                    assert_eq!(error.kind(), ErrorKind::Input);
                } else {
                    assert_eq!(error.kind(), ErrorKind::Runtime);
                }
                assert!(!format!("{error:?} {error}").contains("canary"));
                assert!(session.state().is_err());
            });
        }
    }
}
#[test]
fn budget_overruns_and_reader_unwinds_discard_initialized_sessions() {
    for encrypt in [true, false] {
        with_fixture(0, 0, |session| {
            let data = if encrypt {
                b"abcd".to_vec()
            } else {
                vec![0xEF; 20]
            };
            let mut input = Input::new(&data);
            let error = if encrypt {
                session
                    .encrypt_aes_gcm_reader(&key(), parameters(), &mut input)
                    .unwrap_err()
            } else {
                session
                    .decrypt_aes_gcm_reader(&key(), parameters(), &mut input)
                    .unwrap_err()
            };
            assert_eq!(error.kind(), ErrorKind::Input);
            assert!(session.state().is_err());
        });
        with_fixture(0, 0, |session| {
            let mut input = Input {
                panic: true,
                ..Input::new(b"abc")
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if encrypt {
                    session
                        .encrypt_aes_gcm_reader(&key(), parameters(), &mut input)
                        .unwrap_err();
                } else {
                    session
                        .decrypt_aes_gcm_reader(&key(), parameters(), &mut input)
                        .unwrap_err();
                }
            }));
            assert!(result.is_err());
            assert!(session.state().is_err());
        });
    }
}
