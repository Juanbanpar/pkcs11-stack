// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded readers, redacted errors, parameter lifetimes and pool failure handling.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/hash_ml_dsa_module.rs"]
mod fixture;
use fixture::HashMlDsaModule;
use pkcs11_client::*;
use std::{
    io::{self, Read},
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
};
struct Input {
    bytes: &'static [u8],
    maximum: usize,
    interrupted: bool,
    fail: u8,
}
impl Input {
    fn new(fail: u8) -> Self {
        Self {
            bytes: b"abc",
            maximum: 0,
            interrupted: false,
            fail,
        }
    }
}
impl Read for Input {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.maximum = self.maximum.max(out.len());
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.bytes.is_empty() {
            return match self.fail {
                1 => Err(io::Error::other("reader-redaction-canary")),
                2 => panic!("input unwind"),
                _ => Ok(0),
            };
        }
        out[0] = self.bytes[0];
        self.bytes = &self.bytes[1..];
        Ok(1)
    }
}
fn private() -> PrivateKeyRef {
    PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap()
}
fn public() -> PublicKeyRef {
    PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap()
}
fn parameters() -> HashMlDsaParameters<'static> {
    HashMlDsaParameters {
        parameter_set: MlDsaParameterSet::MlDsa44,
        context: b"",
        hedging: MlDsaHedging::Required,
    }
}
#[test]
fn reader_completion_and_completed_mismatch_preserve_the_same_pool_generation() {
    for verify in [false, true] {
        let fixture = HashMlDsaModule::streaming(3, 2, 0, 0, 1, 0, 0, verify);
        let provider = Provider::load(fixture.path()).unwrap();
        let client = provider
            .client(
                &"pkcs11:token=cmac".parse().unwrap(),
                NonZeroUsize::new(1).unwrap(),
                SigningPolicy::default(),
            )
            .unwrap();
        let generation = client
            .pool()
            .try_acquire(Authentication::None)
            .unwrap()
            .generation();
        for _ in 0..2 {
            let mut reader = Input::new(0);
            if verify {
                client
                    .verify_hash_ml_dsa_reader(
                        &public(),
                        parameters(),
                        &[0xAB; 2420],
                        Authentication::None,
                        &mut reader,
                    )
                    .unwrap();
                assert!(matches!(
                    client.verify_hash_ml_dsa_reader(
                        &public(),
                        parameters(),
                        &[0; 2420],
                        Authentication::None,
                        &mut Input::new(0)
                    ),
                    Err(Error::SignatureMismatch)
                ));
            } else {
                assert_eq!(
                    client
                        .sign_hash_ml_dsa_reader(
                            &private(),
                            parameters(),
                            &MlDsaSigningPolicy::default(),
                            Authentication::None,
                            None,
                            &mut reader
                        )
                        .unwrap(),
                    vec![0xAB; 2420]
                );
            }
            assert_eq!(reader.maximum, 65536);
            assert!(reader.bytes.is_empty());
            assert_eq!(
                client
                    .pool()
                    .try_acquire(Authentication::None)
                    .unwrap()
                    .generation(),
                generation
            );
        }
        client.close().unwrap();
        provider.finalize().unwrap();
    }
}
#[test]
fn read_and_unwind_failures_discard_and_preflight_does_not_read() {
    for verify in [false, true] {
        for fail in [1, 2] {
            let fixture = HashMlDsaModule::streaming(3, 2, 0, 0, 1, 0, 0, verify);
            let provider = Provider::load(fixture.path()).unwrap();
            let client = provider
                .client(
                    &"pkcs11:token=cmac".parse().unwrap(),
                    NonZeroUsize::new(1).unwrap(),
                    SigningPolicy::default(),
                )
                .unwrap();
            let generation = client
                .pool()
                .try_acquire(Authentication::None)
                .unwrap()
                .generation();
            let mut reader = Input::new(fail);
            if verify {
                assert!(
                    client
                        .verify_hash_ml_dsa_reader(
                            &public(),
                            parameters(),
                            &[0; 2419],
                            Authentication::None,
                            &mut reader
                        )
                        .is_err()
                );
            } else {
                assert!(
                    client
                        .sign_hash_ml_dsa_reader(
                            &private(),
                            parameters(),
                            &MlDsaSigningPolicy {
                                parameter_sets: vec![]
                            },
                            Authentication::None,
                            None,
                            &mut reader
                        )
                        .is_err()
                );
            }
            assert_eq!(reader.maximum, 0);
            let result = catch_unwind(AssertUnwindSafe(|| {
                if verify {
                    client.verify_hash_ml_dsa_reader(
                        &public(),
                        parameters(),
                        &[0xAB; 2420],
                        Authentication::None,
                        &mut reader,
                    )
                } else {
                    client
                        .sign_hash_ml_dsa_reader(
                            &private(),
                            parameters(),
                            &MlDsaSigningPolicy::default(),
                            Authentication::None,
                            None,
                            &mut reader,
                        )
                        .map(|_| ())
                }
            }));
            if fail == 2 {
                assert!(result.is_err());
            } else {
                let error = result.unwrap().unwrap_err();
                assert!(matches!(error, Error::SignatureInput));
                assert!(!format!("{error:?}").contains("canary"));
            }
            assert_ne!(
                client
                    .pool()
                    .try_acquire(Authentication::None)
                    .unwrap()
                    .generation(),
                generation
            );
            client.close().unwrap();
            provider.finalize().unwrap();
        }
    }
}
#[test]
fn context_and_pin_borrows_end_after_native_initialization() {
    use secrecy::SecretString;
    let fixture = HashMlDsaModule::streaming(3, 2, 0, 0, 1, 255, 1, false);
    let provider = Provider::load(fixture.path()).unwrap();
    let mut session = provider
        .management(
            &"pkcs11:token=cmac".parse().unwrap(),
            SessionMode::ReadOnly,
            Authentication::None,
        )
        .unwrap();
    let mut operation = {
        let context = vec![0xA5; 255];
        let pin = SecretString::from("1234");
        session
            .start_hash_ml_dsa_signing(
                &private(),
                HashMlDsaParameters {
                    context: &context,
                    ..parameters()
                },
                &MlDsaSigningPolicy::default(),
                Some(Pin::Value(&pin)),
            )
            .unwrap()
    };
    operation.update(b"abc").unwrap();
    operation.finish().unwrap();
    session.close().unwrap();
    provider.finalize().unwrap();
}

#[test]
fn explicit_hash_profile_context_and_pin_borrows_end_at_initialization() {
    use secrecy::SecretString;
    let fixture = HashMlDsaModule::profile(3, 2, 0, 0, "CKM_SHA3_256", 32, false, true, false);
    let provider = Provider::load(fixture.path()).unwrap();
    let mut session = provider
        .management(
            &"pkcs11:token=cmac".parse().unwrap(),
            SessionMode::ReadOnly,
            Authentication::None,
        )
        .unwrap();
    let mut operation = {
        let context = vec![0xA5; 255];
        let pin = SecretString::from("1234");
        session
            .start_hash_ml_dsa_signing(
                &private(),
                HashMlDsaParameters {
                    context: &context,
                    ..parameters()
                }
                .with_hash(DigestAlgorithm::Sha3_256),
                &MlDsaSigningPolicy::default(),
                Some(Pin::Value(&pin)),
            )
            .unwrap()
    };
    operation.update(b"abc").unwrap();
    operation.finish().unwrap();
    session.close().unwrap();
    provider.finalize().unwrap();
}
