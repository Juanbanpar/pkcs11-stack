// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reader failure, exclusive ownership and init-only parameter/PIN lifetimes.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/ml_dsa_stream_module.rs"]
mod fixture;
use fixture::MlDsaStreamModule;
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
fn key() -> PrivateKeyRef {
    PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap()
}
fn parameters() -> MlDsaParameters<'static> {
    MlDsaParameters {
        parameter_set: MlDsaParameterSet::MlDsa44,
        context: &[],
        hedging: MlDsaHedging::Required,
    }
}
#[test]
fn bounded_reader_guard_completion_and_explicit_cancellation() {
    let fixture = MlDsaStreamModule::new(3, 2, 0, 0, 1, 0, 0);
    let provider = Provider::load(fixture.path()).unwrap();
    let mut session = provider
        .management(
            &"pkcs11:token=cmac".parse().unwrap(),
            SessionMode::ReadOnly,
            Authentication::None,
        )
        .unwrap();
    let policy = MlDsaSigningPolicy::default();
    assert!(
        session
            .ml_dsa_streaming_capabilities(&key())
            .unwrap()
            .can_sign
    );
    for message in [&[][..], b"abc"] {
        let mut input = Input {
            bytes: message,
            ..Input::new(false)
        };
        let signature = session
            .sign_ml_dsa_reader(&key(), parameters(), &policy, None, &mut input)
            .unwrap();
        assert_eq!(signature, vec![0xAB; 2420]);
        assert_eq!(input.maximum_buffer, 65536);
        assert!(input.bytes.is_empty());
        session.state().unwrap();
    }
    let mut operation = session
        .start_ml_dsa_signing(&key(), parameters(), &policy, None)
        .unwrap();
    assert_eq!(operation.parameter_set(), MlDsaParameterSet::MlDsa44);
    operation.update(b"a").unwrap();
    operation.cancel().unwrap();
    session.state().unwrap();
    session.close().unwrap();
    provider.finalize().unwrap();
}
#[test]
fn context_pin_borrows_end_at_init_and_preflight_does_not_read() {
    let fixture = MlDsaStreamModule::new(3, 2, 0, 0, 1, 255, 1);
    let provider = Provider::load(fixture.path()).unwrap();
    let mut session = provider
        .management(
            &"pkcs11:token=cmac".parse().unwrap(),
            SessionMode::ReadOnly,
            Authentication::None,
        )
        .unwrap();
    let policy = MlDsaSigningPolicy::default();
    let mut input = Input::new(false);
    assert!(
        session
            .sign_ml_dsa_reader(
                &key(),
                MlDsaParameters {
                    context: &[0; 256],
                    ..parameters()
                },
                &policy,
                None,
                &mut input
            )
            .is_err()
    );
    assert!(
        session
            .sign_ml_dsa_reader(
                &key(),
                parameters(),
                &MlDsaSigningPolicy {
                    parameter_sets: vec![]
                },
                None,
                &mut input
            )
            .is_err()
    );
    assert!(matches!(
        session.sign_ml_dsa_reader(&key(), parameters(), &policy, None, &mut input),
        Err(Error::Runtime(
            pkcs11_runtime::Error::ContextAuthenticationRequired
        ))
    ));
    assert_eq!(input.maximum_buffer, 0);
    session.state().unwrap();
    let mut operation = {
        let context = vec![0xA5; 255];
        let pin = secrecy::SecretString::from("1234");
        session
            .start_ml_dsa_signing(
                &key(),
                MlDsaParameters {
                    context: &context,
                    ..parameters()
                },
                &policy,
                Some(Pin::Value(&pin)),
            )
            .unwrap()
    };
    operation.update(b"abc").unwrap();
    operation.finish().unwrap();
    session.state().unwrap();
    let debug = format!(
        "{:?}",
        MlDsaParameters {
            context: b"context canary",
            ..parameters()
        }
    );
    assert!(!debug.contains("canary"));
    session.close().unwrap();
    provider.finalize().unwrap();
}
#[test]
fn read_update_and_final_failures_discard_without_diagnostic_leaks() {
    for fault in [0, 13, 14, 15, 21, 22, 27] {
        let fixture = MlDsaStreamModule::new(3, 2, fault, 0, 1, 0, 0);
        let provider = Provider::load(fixture.path()).unwrap();
        let mut session = provider
            .management(
                &"pkcs11:token=cmac".parse().unwrap(),
                SessionMode::ReadOnly,
                Authentication::None,
            )
            .unwrap();
        let error = session
            .sign_ml_dsa_reader(
                &key(),
                parameters(),
                &MlDsaSigningPolicy::default(),
                None,
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
        session.close().unwrap();
        provider.finalize().unwrap();
    }
}
#[test]
fn unwinding_a_reader_discards_the_initialized_session() {
    struct Panics;
    impl Read for Panics {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("read panic canary")
        }
    }
    let fixture = MlDsaStreamModule::new(3, 2, 0, 0, 1, 0, 0);
    let provider = Provider::load(fixture.path()).unwrap();
    let mut session = provider
        .management(
            &"pkcs11:token=cmac".parse().unwrap(),
            SessionMode::ReadOnly,
            Authentication::None,
        )
        .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        session.sign_ml_dsa_reader(
            &key(),
            parameters(),
            &MlDsaSigningPolicy::default(),
            None,
            &mut Panics,
        )
    }));
    assert!(result.is_err());
    assert!(session.state().is_err());
    session.close().unwrap();
    provider.finalize().unwrap();
}
