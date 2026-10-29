// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reader failure, exclusive ownership and init-only context/signature lifetimes.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/ml_dsa_verify_module.rs"]
mod fixture;
use fixture::MlDsaVerifyModule;
use pkcs11_client::*;
use std::io::{self, Read};
struct Input {
    bytes: &'static [u8],
    maximum_buffer: usize,
    interrupted: bool,
    fail: bool,
}
impl Input {
    fn new(fail: bool) -> Self {
        Self {
            bytes: b"abc",
            maximum_buffer: 0,
            interrupted: false,
            fail,
        }
    }
}
impl Read for Input {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.maximum_buffer = self.maximum_buffer.max(output.len());
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.bytes.is_empty() {
            return if self.fail {
                Err(io::Error::other("reader error canary"))
            } else {
                Ok(0)
            };
        }
        output[0] = self.bytes[0];
        self.bytes = &self.bytes[1..];
        Ok(1)
    }
}
fn key() -> PublicKeyRef {
    PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap()
}
fn parameters() -> MlDsaParameters<'static> {
    MlDsaParameters {
        parameter_set: MlDsaParameterSet::MlDsa44,
        context: &[],
        hedging: MlDsaHedging::Required,
    }
}

fn with_fixture(fault: u8, length: usize, test: impl FnOnce(&mut ManagementSession<'_>)) {
    let fixture = MlDsaVerifyModule::new(3, 2, fault, 0, 1, length);
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
fn bounded_empty_interrupted_readers_and_init_only_context_signature_borrows() {
    with_fixture(0, 0, |session| {
        assert!(
            session
                .ml_dsa_verification_capabilities(&key())
                .unwrap()
                .can_stream
        );
        for message in [&[][..], b"abc"] {
            let mut input = Input {
                bytes: message,
                ..Input::new(false)
            };
            session
                .verify_ml_dsa_reader(&key(), parameters(), &[0xAB; 2420], &mut input)
                .unwrap();
            assert_eq!(input.maximum_buffer, 65536);
            assert!(input.bytes.is_empty());
            session.state().unwrap();
        }
        session
            .verify_ml_dsa_signature_first(&key(), &parameters().request(b"abc"), &[0xAB; 2420])
            .unwrap();
        let mut operation = session
            .start_ml_dsa_verification(&key(), parameters(), &[0xAB; 2420])
            .unwrap();
        operation.update(b"a").unwrap();
        operation.cancel().unwrap();
        session.state().unwrap();
    });
    with_fixture(0, 255, |session| {
        let mut operation = {
            let context = vec![0xA5; 255];
            let signature = vec![0xAB; 2420];
            session
                .start_ml_dsa_verification(
                    &key(),
                    MlDsaParameters {
                        context: &context,
                        ..parameters()
                    },
                    &signature,
                )
                .unwrap()
        };
        assert_eq!(operation.parameter_set(), MlDsaParameterSet::MlDsa44);
        assert!(!format!("{operation:?}").contains("171"));
        operation.update(b"abc").unwrap();
        operation.finish().unwrap();
    });
}
#[test]
fn preflight_does_not_consume_input_and_completed_mismatches_permit_reuse() {
    with_fixture(0, 0, |session| {
        let mut reader = Input::new(false);
        assert!(matches!(
            session.verify_ml_dsa_reader(&key(), parameters(), &[], &mut reader),
            Err(Error::SignatureMismatch)
        ));
        assert!(
            session
                .verify_ml_dsa_reader(
                    &key(),
                    MlDsaParameters {
                        context: &[0; 256],
                        ..parameters()
                    },
                    &[0xAB; 2420],
                    &mut reader
                )
                .is_err()
        );
        assert_eq!(reader.maximum_buffer, 0);
        session.state().unwrap();
        let mut signature = vec![0xAB; 2420];
        signature[0] = 0;
        let error = session
            .verify_ml_dsa_reader(&key(), parameters(), &signature, &mut reader)
            .unwrap_err();
        assert!(matches!(error, Error::SignatureMismatch));
        assert_eq!(error.kind(), ErrorKind::Client);
        session.state().unwrap();
        let error = session
            .verify_ml_dsa_signature_first(&key(), &parameters().request(b"abc"), &signature)
            .unwrap_err();
        assert!(matches!(error, Error::SignatureMismatch));
        session.state().unwrap();
    });
    for fault in [6, 8, 9] {
        with_fixture(fault, 0, |session| {
            let mut reader = Input::new(false);
            assert!(
                session
                    .verify_ml_dsa_reader(&key(), parameters(), &[0xAB; 2420], &mut reader)
                    .is_err()
            );
            assert_eq!(reader.maximum_buffer, 0);
            session.state().unwrap();
        });
    }
}
#[test]
fn read_and_native_failures_discard_without_diagnostic_leaks() {
    for fault in [0, 11, 12, 13, 14, 15, 21, 22, 26, 29, 30] {
        with_fixture(fault, 0, |session| {
            let error = session
                .verify_ml_dsa_reader(
                    &key(),
                    parameters(),
                    &[0xAB; 2420],
                    &mut Input::new(fault == 0),
                )
                .unwrap_err();
            if fault == 0 {
                assert!(matches!(error, Error::SignatureInput));
                assert_eq!(error.kind(), ErrorKind::Input);
            } else {
                assert_eq!(error.kind(), ErrorKind::Runtime);
            }
            assert!(!format!("{error:?} {error}").contains("canary"));
            assert!(session.state().is_err());
        });
    }
}
#[test]
fn unwind_and_abandonment_discard_initialized_sessions() {
    struct Panics;
    impl Read for Panics {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("reader canary")
        }
    }
    with_fixture(0, 0, |session| {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            session.verify_ml_dsa_reader(&key(), parameters(), &[0xAB; 2420], &mut Panics)
        }));
        assert!(result.is_err());
        assert!(session.state().is_err());
    });
    with_fixture(0, 0, |session| {
        let operation = session
            .start_ml_dsa_verification(&key(), parameters(), &[0xAB; 2420])
            .unwrap();
        drop(operation);
        assert!(session.state().is_err());
    });
}

#[test]
fn pooled_signature_first_readers_reuse_mismatches_and_discard_read_errors() {
    let module = MlDsaVerifyModule::new(3, 2, 0, 0, 1, 0);
    let provider = Provider::load(module.path()).unwrap();
    let client = provider
        .client(
            &"pkcs11:token=cmac".parse().unwrap(),
            std::num::NonZeroUsize::new(1).unwrap(),
            SigningPolicy::default(),
        )
        .unwrap();
    let generation = || {
        client
            .pool()
            .try_acquire(Authentication::None)
            .unwrap()
            .generation()
    };
    let before = generation();
    client
        .verify_ml_dsa_reader(
            &key(),
            parameters(),
            &[0xAB; 2420],
            Authentication::None,
            &mut Input::new(false),
        )
        .unwrap();
    assert!(matches!(
        client.verify_ml_dsa_reader(
            &key(),
            parameters(),
            &[0; 2420],
            Authentication::None,
            &mut Input::new(false)
        ),
        Err(Error::SignatureMismatch)
    ));
    assert_eq!(generation(), before);
    assert!(matches!(
        client.verify_ml_dsa_reader(
            &key(),
            parameters(),
            &[0xAB; 2420],
            Authentication::None,
            &mut Input::new(true)
        ),
        Err(Error::SignatureInput)
    ));
    assert_ne!(generation(), before);
    client.close().unwrap();
    provider.finalize().unwrap();
}
