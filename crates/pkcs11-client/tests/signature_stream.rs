// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reader bounds, ownership, preflight and failure contracts for signatures.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/signature_stream_module.rs"]
mod fixture;
use fixture::SignatureStreamModule;
use pkcs11_client::*;
use std::io::{self, Read};
struct Input {
    remaining: &'static [u8],
    maximum_buffer: usize,
    interrupted: bool,
    fail: bool,
}
impl Input {
    fn new(fail: bool) -> Self {
        Self {
            remaining: b"abc",
            maximum_buffer: 0,
            interrupted: false,
            fail,
        }
    }
}
impl Read for Input {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.maximum_buffer = self.maximum_buffer.max(out.len());
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.remaining.is_empty() {
            return if self.fail {
                Err(io::Error::other("signature I/O canary"))
            } else {
                Ok(0)
            };
        }
        out[0] = self.remaining[0];
        self.remaining = &self.remaining[1..];
        Ok(1)
    }
}
fn parameters() -> SignatureParameters {
    SignatureParameters {
        algorithm: SignatureAlgorithm::RsaPkcs1,
        digest: DigestAlgorithm::Sha224,
        pss: None,
    }
}
fn policy(hashing: HashingPolicy) -> SigningPolicy {
    let mut policy = SigningPolicy {
        hashing,
        ..Default::default()
    };
    policy.digests.push(DigestAlgorithm::Sha224);
    policy
}
fn private() -> PrivateKeyRef {
    PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap()
}
fn public() -> PublicKeyRef {
    PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap()
}
#[test]
fn reader_chunking_options_guard_completion_and_cancellation() {
    for hashing in [
        HashingPolicy::TokenOnly,
        HashingPolicy::AllowSoftware,
        HashingPolicy::SoftwareOnly,
    ] {
        let fixture = SignatureStreamModule::new(3, 2, 0, 0, false, 224, 0);
        let provider = Provider::load(fixture.path()).unwrap();
        let mut session = provider
            .management(
                &"pkcs11:token=cmac".parse().unwrap(),
                SessionMode::ReadOnly,
                Authentication::None,
            )
            .unwrap();
        let policy = policy(hashing);
        let choices = session
            .streaming_signing_options(&private(), &policy)
            .unwrap();
        assert!(
            choices
                .choices
                .iter()
                .any(|choice| choice.parameters == parameters())
        );
        assert!(
            session
                .streaming_verification_options(&public(), &policy)
                .unwrap()
                .iter()
                .any(|choice| choice.parameters == parameters())
        );
        let mut input = Input::new(false);
        let signature = session
            .sign_reader(&private(), parameters(), &policy, None, &mut input)
            .unwrap();
        assert_eq!(signature, vec![0xAB; 256]);
        assert_eq!(input.maximum_buffer, 64 * 1024);
        assert!(input.remaining.is_empty());
        for supplied in [signature.clone(), vec![], vec![0; 256]] {
            let mut input = Input::new(false);
            let result = session.verify_token_reader(
                &public(),
                parameters(),
                &policy,
                &mut input,
                &supplied,
            );
            if supplied == signature {
                result.unwrap();
            } else {
                assert!(matches!(result, Err(Error::SignatureMismatch)));
            }
            assert_eq!(input.maximum_buffer, 64 * 1024);
            assert!(input.remaining.is_empty());
            session.state().unwrap();
        }
        let mut operation = session
            .start_signing(&private(), parameters(), &policy, None)
            .unwrap();
        operation.update(b"a").unwrap();
        operation.cancel().unwrap();
        let mut operation = session
            .start_verification(&public(), parameters(), &policy)
            .unwrap();
        operation.update(b"a").unwrap();
        operation.cancel().unwrap();
        session.state().unwrap();
        session.close().unwrap();
        provider.finalize().unwrap();
    }
}
#[test]
fn read_and_native_failures_discard_both_directions_without_diagnostic_leaks() {
    for verification in [false, true] {
        for (hashing, fault) in [
            (HashingPolicy::TokenOnly, 0),
            (HashingPolicy::SoftwareOnly, 0),
            (HashingPolicy::TokenOnly, 23),
            (HashingPolicy::TokenOnly, 24),
            (HashingPolicy::SoftwareOnly, 25),
        ] {
            let fixture = SignatureStreamModule::new(3, 2, fault, 0, false, 224, 0);
            let provider = Provider::load(fixture.path()).unwrap();
            let mut session = provider
                .management(
                    &"pkcs11:token=cmac".parse().unwrap(),
                    SessionMode::ReadOnly,
                    Authentication::None,
                )
                .unwrap();
            let mut input = Input::new(fault == 0);
            let policy = policy(hashing);
            let error = if verification {
                session
                    .verify_token_reader(&public(), parameters(), &policy, &mut input, &[0xAB; 256])
                    .unwrap_err()
            } else {
                session
                    .sign_reader(&private(), parameters(), &policy, None, &mut input)
                    .unwrap_err()
            };
            if fault == 0 {
                assert!(matches!(error, Error::SignatureInput));
                assert_eq!(error.kind(), ErrorKind::Input);
            } else {
                assert_eq!(error.kind(), ErrorKind::Runtime);
            }
            assert!(!format!("{error} {error:?}").contains("canary"));
            assert!(session.state().is_err());
            session.close().unwrap();
            provider.finalize().unwrap();
        }
    }
}
#[test]
fn context_preflight_does_not_read_and_pin_lifetime_ends_after_initialization() {
    let fixture = SignatureStreamModule::new(3, 2, 0, 0, false, 224, 1);
    let provider = Provider::load(fixture.path()).unwrap();
    let mut session = provider
        .management(
            &"pkcs11:token=cmac".parse().unwrap(),
            SessionMode::ReadOnly,
            Authentication::None,
        )
        .unwrap();
    let policy = policy(HashingPolicy::TokenOnly);
    let mut input = Input::new(false);
    assert!(matches!(
        session.sign_reader(&private(), parameters(), &policy, None, &mut input),
        Err(Error::Runtime(
            pkcs11_runtime::Error::ContextAuthenticationRequired
        ))
    ));
    assert_eq!(input.maximum_buffer, 0);
    session.state().unwrap();
    let mut operation = {
        let pin = secrecy::SecretString::from("1234");
        session
            .start_signing(&private(), parameters(), &policy, Some(Pin::Value(&pin)))
            .unwrap()
    };
    operation.update(b"abc").unwrap();
    operation.finish().unwrap();
    session.state().unwrap();
    session.close().unwrap();
    provider.finalize().unwrap();
}

#[test]
fn reader_unwind_discards_initialized_signing_and_verification() {
    struct Panics;
    impl Read for Panics {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("input panic canary")
        }
    }
    for verification in [false, true] {
        for hashing in [HashingPolicy::TokenOnly, HashingPolicy::SoftwareOnly] {
            let fixture = SignatureStreamModule::new(3, 2, 0, 0, false, 224, 0);
            let provider = Provider::load(fixture.path()).unwrap();
            let mut session = provider
                .management(
                    &"pkcs11:token=cmac".parse().unwrap(),
                    SessionMode::ReadOnly,
                    Authentication::None,
                )
                .unwrap();
            let policy = policy(hashing);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if verification {
                    session
                        .verify_token_reader(
                            &public(),
                            parameters(),
                            &policy,
                            &mut Panics,
                            &[0xAB; 256],
                        )
                        .unwrap();
                } else {
                    session
                        .sign_reader(&private(), parameters(), &policy, None, &mut Panics)
                        .unwrap();
                }
            }));
            assert!(result.is_err());
            assert!(session.state().is_err());
            session.close().unwrap();
            provider.finalize().unwrap();
        }
    }
}

#[test]
fn pooled_readers_reuse_completed_operations_and_discard_failed_streams() {
    use std::num::NonZeroUsize;
    for hashing in [HashingPolicy::TokenOnly, HashingPolicy::SoftwareOnly] {
        let fixture = SignatureStreamModule::new(3, 2, 0, 0, false, 224, 0);
        let provider = Provider::load(fixture.path()).unwrap();
        let client = provider
            .client(
                &"pkcs11:token=cmac".parse().unwrap(),
                NonZeroUsize::new(1).unwrap(),
                policy(hashing),
            )
            .unwrap();
        let generation = || {
            client
                .pool()
                .try_acquire(Authentication::None)
                .unwrap()
                .generation()
        };
        let initial = generation();
        client
            .streaming_plan(&private(), parameters(), Authentication::None)
            .unwrap();
        let mut input = Input::new(false);
        let signature = client
            .sign_reader(
                &private(),
                parameters(),
                Authentication::None,
                None,
                &mut input,
            )
            .unwrap();
        assert_eq!(input.maximum_buffer, 64 * 1024);
        assert_eq!(signature, vec![0xAB; 256]);
        for tag in [&signature[..], &[0; 256][..]] {
            let mut input = Input::new(false);
            let result = client.verify_token_reader(
                &public(),
                parameters(),
                Authentication::None,
                &mut input,
                tag,
            );
            if tag == signature {
                result.unwrap();
            } else {
                assert!(matches!(result, Err(Error::SignatureMismatch)));
            }
            assert_eq!(generation(), initial);
        }
        for verification in [false, true] {
            let before = generation();
            let mut input = Input::new(true);
            let error = if verification {
                client
                    .verify_token_reader(
                        &public(),
                        parameters(),
                        Authentication::None,
                        &mut input,
                        &signature,
                    )
                    .unwrap_err()
            } else {
                client
                    .sign_reader(
                        &private(),
                        parameters(),
                        Authentication::None,
                        None,
                        &mut input,
                    )
                    .unwrap_err()
            };
            assert!(matches!(error, Error::SignatureInput));
            assert!(!error.to_string().contains("canary"));
            assert_ne!(generation(), before);
        }
        client.close().unwrap();
        provider.finalize().unwrap();
    }
}
