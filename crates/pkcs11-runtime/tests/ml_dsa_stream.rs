// SPDX-License-Identifier: MIT OR Apache-2.0
//! Official 3.2 parameter ABI, bounded output and exclusive streaming lifecycle.
#![cfg(unix)]
#[path = "fixtures/ml_dsa_stream_module.rs"]
mod fixture;
use fixture::MlDsaStreamModule;
use pkcs11_runtime::*;
use secrecy::SecretString;
const SETS: [MlDsaParameterSet; 3] = [
    MlDsaParameterSet::MlDsa44,
    MlDsaParameterSet::MlDsa65,
    MlDsaParameterSet::MlDsa87,
];
fn key() -> PrivateKeyRef {
    PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap()
}
fn parameters(parameter: u8) -> MlDsaParameters<'static> {
    MlDsaParameters {
        parameter_set: SETS[usize::from(parameter)],
        context: &[],
        hedging: MlDsaHedging::Required,
    }
}
#[test]
fn all_parameter_sets_hedging_contexts_and_selected_tables() {
    for (major, minor) in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        for parameter in 0..3 {
            for (hedge, context_length, auth) in [(0, 0, 0), (1, 255, 1), (2, 1, 0)] {
                let fixture =
                    MlDsaStreamModule::new(major, minor, 0, parameter, hedge, context_length, auth);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                let pin = SecretString::from("1234");
                let policy = MlDsaSigningPolicy::default();
                let context = vec![0xA5; context_length];
                let parameters = MlDsaParameters {
                    context: &context,
                    hedging: match hedge {
                        0 => MlDsaHedging::Preferred,
                        1 => MlDsaHedging::Required,
                        _ => MlDsaHedging::Deterministic,
                    },
                    ..parameters(parameter)
                };
                let caps = session.ml_dsa_streaming_capabilities(&key()).unwrap();
                assert!(caps.can_sign);
                assert_eq!(caps.parameter_set, parameters.parameter_set);
                assert_eq!(caps.always_authenticate, auth != 0);
                for message in [&[][..], b"abc"] {
                    let mut operation = session
                        .start_ml_dsa_signing(
                            &key(),
                            parameters,
                            &policy,
                            (auth != 0).then_some(Pin::Value(&pin)),
                        )
                        .unwrap();
                    assert_eq!(operation.parameter_set(), parameters.parameter_set);
                    assert!(!format!("{operation:?}").contains("1234"));
                    operation.update(&[]).unwrap();
                    for chunk in message.chunks(1) {
                        operation.update(chunk).unwrap();
                    }
                    let signature = operation.finish().unwrap();
                    assert_eq!(
                        signature,
                        vec![0xAB; parameters.parameter_set.signature_length()]
                    );
                    session.info().unwrap();
                    // Existing one-shot signatures also use caller-bounded storage.
                    let signature = session
                        .sign_ml_dsa(
                            &key(),
                            &parameters.request(message),
                            &policy,
                            (auth != 0).then_some(Pin::Value(&pin)),
                        )
                        .unwrap();
                    assert_eq!(signature.len(), parameters.parameter_set.signature_length());
                }
                session.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
#[test]
fn invalid_requests_permissions_and_missing_multipart_functions_fail_before_init() {
    for fault in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 23, 24] {
        let fixture = MlDsaStreamModule::new(3, 2, fault, 0, 1, 0, 1);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let policy = MlDsaSigningPolicy::default();
        let parameters = parameters(0);
        let pin = SecretString::from("1234");
        assert!(
            session
                .start_ml_dsa_signing(
                    &key(),
                    MlDsaParameters {
                        context: &[0; 256],
                        ..parameters
                    },
                    &policy,
                    Some(Pin::Value(&pin))
                )
                .is_err()
        );
        assert!(
            session
                .start_ml_dsa_signing(
                    &key(),
                    parameters,
                    &MlDsaSigningPolicy {
                        parameter_sets: vec![]
                    },
                    Some(Pin::Value(&pin))
                )
                .is_err()
        );
        if fault == 0 {
            assert!(matches!(
                session.start_ml_dsa_signing(&key(), parameters, &policy, None),
                Err(Error::ContextAuthenticationRequired)
            ));
        } else {
            assert!(
                session
                    .start_ml_dsa_signing(&key(), parameters, &policy, Some(Pin::Value(&pin)))
                    .is_err()
            );
        }
        assert_eq!(session.info().unwrap().device_error(), 0);
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
    let fixture = MlDsaStreamModule::new(2, 40, 10, 0, 1, 0, 0);
    let module = Module::load(fixture.path()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
        .unwrap();
    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
    assert!(!module.supports_function(Function::Sign));
    let mut operation = session
        .start_ml_dsa_signing(&key(), parameters(0), &MlDsaSigningPolicy::default(), None)
        .unwrap();
    operation.update(b"abc").unwrap();
    operation.finish().unwrap();
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
#[test]
fn failed_and_abandoned_operations_are_discarded_without_implicit_cancellation() {
    for fault in [0, 11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 26, 27] {
        let fixture = MlDsaStreamModule::new(3, 2, fault, 2, 1, 0, 1);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let pin = SecretString::from("1234");
        match session.start_ml_dsa_signing(
            &key(),
            parameters(2),
            &MlDsaSigningPolicy::default(),
            Some(Pin::Value(&pin)),
        ) {
            Err(_) => assert!(matches!(fault, 11 | 12 | 26)),
            Ok(mut operation) => match fault {
                0 => drop(operation),
                13 | 14 | 21 | 22 => {
                    assert!(operation.update(b"abc").is_err());
                    assert!(matches!(operation.update(b"retry"), Err(Error::Closed)));
                    assert!(matches!(operation.cancel(), Err(Error::Closed)));
                }
                _ => {
                    operation.update(b"abc").unwrap();
                    assert!(operation.finish().is_err());
                }
            },
        }
        assert!(session.info().is_err());
        let calls = watcher.info().unwrap().device_error();
        assert_eq!(calls >> 24, 1);
        assert_eq!(calls & 0xF, 0);
        assert_eq!(calls >> 4 & 0xF, u64::from(matches!(fault, 15..=18 | 27)));
        session.close().unwrap();
        watcher.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
#[test]
fn bounded_single_part_completion_also_discards_malformed_output() {
    for auth in [0, 1] {
        for fault in [15, 16, 17, 18, 27] {
            let fixture = MlDsaStreamModule::new(3, 2, fault, 1, 1, 0, auth);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let pin = SecretString::from("1234");
            assert!(
                session
                    .sign_ml_dsa(
                        &key(),
                        &parameters(1).request(b"abc"),
                        &MlDsaSigningPolicy::default(),
                        (auth != 0).then_some(Pin::Value(&pin))
                    )
                    .is_err()
            );
            assert!(session.info().is_err());
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn explicit_cancellation_restores_only_confirmed_native_termination() {
    for (major, minor, fault) in [
        (2, 40, 0),
        (3, 0, 0),
        (3, 1, 0),
        (3, 2, 0),
        (3, 2, 19),
        (3, 2, 20),
        (3, 2, 25),
    ] {
        let fixture = MlDsaStreamModule::new(major, minor, fault, 0, 1, 0, 0);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let mut operation = session
            .start_ml_dsa_signing(&key(), parameters(0), &MlDsaSigningPolicy::default(), None)
            .unwrap();
        operation.update(b"a").unwrap();
        let result = operation.cancel();
        if major >= 3 && fault == 0 {
            result.unwrap();
            session.info().unwrap();
            let mut operation = session
                .start_ml_dsa_signing(&key(), parameters(0), &MlDsaSigningPolicy::default(), None)
                .unwrap();
            operation.update(b"abc").unwrap();
            operation.finish().unwrap();
        } else {
            assert!(result.is_err());
            assert!(session.info().is_err());
        }
        assert_eq!(
            watcher.info().unwrap().device_error() & 0xF,
            u64::from(major >= 3 && fault != 20)
        );
        session.close().unwrap();
        watcher.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}

#[test]
fn untouched_stream_establishes_empty_multipart_input_before_finalization() {
    for fault in [0, 13] {
        let fixture = MlDsaStreamModule::new(3, 2, fault, 0, 1, 0, 0);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
        let operation = session
            .start_ml_dsa_signing(&key(), parameters(0), &MlDsaSigningPolicy::default(), None)
            .unwrap();
        let result = operation.finish();
        if fault == 0 {
            assert_eq!(result.unwrap(), vec![0xAB; 2420]);
            session.info().unwrap();
        } else {
            assert!(result.is_err());
            assert!(session.info().is_err());
        }
        let calls = watcher.info().unwrap().device_error();
        assert_eq!(calls >> 8 & 0xFF, 1);
        assert_eq!(calls >> 4 & 0xF, u64::from(fault == 0));
        session.close().unwrap();
        watcher.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
