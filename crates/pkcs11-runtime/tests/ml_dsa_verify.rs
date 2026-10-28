// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent 3.2 signature-first ABI, permissions and session lifecycle.
#![cfg(unix)]
#[path = "fixtures/ml_dsa_verify_module.rs"]
mod fixture;
use fixture::MlDsaVerifyModule;
use pkcs11_runtime::*;
const SETS: [MlDsaParameterSet; 3] = [
    MlDsaParameterSet::MlDsa44,
    MlDsaParameterSet::MlDsa65,
    MlDsaParameterSet::MlDsa87,
];
fn key() -> PublicKeyRef {
    PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap()
}
fn parameters(parameter: u8) -> MlDsaParameters<'static> {
    MlDsaParameters {
        parameter_set: SETS[usize::from(parameter)],
        context: &[],
        hedging: MlDsaHedging::Required,
    }
}
fn with_fixture(
    fixture: MlDsaVerifyModule,
    options: ModuleOptions,
    test: impl FnOnce(&Module, &mut Session<'_>, &Session<'_>),
) {
    let module = Module::load_with_options(fixture.path(), options).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
        .unwrap();
    let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
    test(&module, &mut session, &watcher);
    session.close().unwrap();
    watcher.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
#[test]
fn all_parameter_sets_contexts_and_hedging_use_exact_signature_first_abi() {
    for parameter in 0..3 {
        for (hedge, length) in [(0, 0), (1, 255), (2, 1)] {
            let fixture = MlDsaVerifyModule::new(3, 2, 0, parameter, hedge, length);
            with_fixture(fixture, ModuleOptions::default(), |module, session, _| {
                assert!(!module.supports_function(Function::Verify));
                let context = vec![0xA5; length];
                let parameters = MlDsaParameters {
                    context: &context,
                    hedging: match hedge {
                        0 => MlDsaHedging::Preferred,
                        1 => MlDsaHedging::Required,
                        _ => MlDsaHedging::Deterministic,
                    },
                    ..parameters(parameter)
                };
                let signature = vec![0xAB; parameters.parameter_set.signature_length()];
                let caps = session.ml_dsa_verification_capabilities(&key()).unwrap();
                assert!(caps.can_verify && caps.can_stream);
                assert_eq!(caps.parameter_set, parameters.parameter_set);
                for message in [&[][..], b"abc"] {
                    session
                        .verify_ml_dsa_signature_first(
                            &key(),
                            &parameters.request(message),
                            &signature,
                        )
                        .unwrap();
                    let mut operation = session
                        .start_ml_dsa_verification(&key(), parameters, &signature)
                        .unwrap();
                    assert_eq!(operation.parameter_set(), parameters.parameter_set);
                    if !message.is_empty() {
                        operation.update(&[]).unwrap();
                    }
                    for chunk in message.chunks(1) {
                        operation.update(chunk).unwrap();
                    }
                    operation.finish().unwrap();
                    session.info().unwrap();
                }
            });
        }
    }
}
#[test]
fn selected_table_and_independent_single_stream_pointers_are_required() {
    for (major, minor, fault) in [
        (2, 40, 0),
        (3, 0, 0),
        (3, 1, 0),
        (3, 2, 6),
        (3, 2, 7),
        (3, 2, 8),
        (3, 2, 9),
    ] {
        with_fixture(
            MlDsaVerifyModule::new(major, minor, fault, 0, 1, 0),
            ModuleOptions::default(),
            |_, session, _| {
                let signature = vec![0xAB; 2420];
                let caps = session.ml_dsa_verification_capabilities(&key()).unwrap();
                let single = major == 3 && minor == 2 && !matches!(fault, 6 | 7);
                let stream = major == 3 && minor == 2 && !matches!(fault, 6 | 8 | 9);
                assert_eq!(caps.can_verify, single);
                assert_eq!(caps.can_stream, stream);
                let result = session.verify_ml_dsa_signature_first(
                    &key(),
                    &parameters(0).request(b"abc"),
                    &signature,
                );
                assert_eq!(result.is_ok(), single);
                if stream {
                    let mut operation = session
                        .start_ml_dsa_verification(&key(), parameters(0), &signature)
                        .unwrap();
                    operation.update(b"abc").unwrap();
                    operation.finish().unwrap();
                } else {
                    assert!(
                        session
                            .start_ml_dsa_verification(&key(), parameters(0), &signature)
                            .is_err()
                    );
                }
                session.info().unwrap();
            },
        );
    }
    with_fixture(
        MlDsaVerifyModule::new(3, 2, 0, 0, 1, 0),
        ModuleOptions {
            interface: InterfaceSelection::Exact(InterfaceVersion::V2_40),
        },
        |module, session, _| {
            assert!(module.interface().legacy);
            assert!(
                !session
                    .ml_dsa_verification_capabilities(&key())
                    .unwrap()
                    .can_stream
            );
            assert!(
                session
                    .start_ml_dsa_verification(&key(), parameters(0), &vec![0xAB; 2420])
                    .is_err()
            );
            assert_eq!(session.info().unwrap().device_error(), 0);
        },
    );
}
#[test]
fn bad_parameters_signatures_permissions_and_metadata_fail_before_init() {
    for fault in [0, 1, 2, 3, 4, 5, 23, 24] {
        with_fixture(
            MlDsaVerifyModule::new(3, 2, fault, 0, 1, 0),
            ModuleOptions::default(),
            |_, session, _| {
                for signature in [&[][..], &[0xAB; 2419], &[0xAB; 2421]] {
                    assert!(matches!(
                        session.start_ml_dsa_verification(&key(), parameters(0), signature),
                        Err(Error::SignatureMismatch)
                    ));
                    assert!(matches!(
                        session.verify_ml_dsa_signature_first(
                            &key(),
                            &parameters(0).request(b"abc"),
                            signature
                        ),
                        Err(Error::SignatureMismatch)
                    ));
                }
                assert!(
                    session
                        .start_ml_dsa_verification(
                            &key(),
                            MlDsaParameters {
                                context: &[0; 256],
                                ..parameters(0)
                            },
                            &[0xAB; 2420]
                        )
                        .is_err()
                );
                if fault != 0 {
                    assert!(
                        session
                            .start_ml_dsa_verification(&key(), parameters(0), &[0xAB; 2420])
                            .is_err()
                    );
                    assert!(
                        session
                            .verify_ml_dsa_signature_first(
                                &key(),
                                &parameters(0).request(b"abc"),
                                &[0xAB; 2420]
                            )
                            .is_err()
                    );
                }
                assert_eq!(session.info().unwrap().device_error(), 0);
            },
        );
    }
}
#[test]
fn completed_single_and_multipart_mismatches_permit_reuse() {
    for fault in [0, 16, 17, 27, 28] {
        with_fixture(
            MlDsaVerifyModule::new(3, 2, fault, 0, 1, 0),
            ModuleOptions::default(),
            |_, session, _| {
                let mut signature = vec![0xAB; 2420];
                signature[0] = 0;
                assert!(matches!(
                    session.verify_ml_dsa_signature_first(
                        &key(),
                        &parameters(0).request(b"abc"),
                        &signature
                    ),
                    Err(Error::SignatureMismatch)
                ));
                session.info().unwrap();
                let mut operation = session
                    .start_ml_dsa_verification(&key(), parameters(0), &signature)
                    .unwrap();
                operation.update(b"abc").unwrap();
                assert!(matches!(operation.finish(), Err(Error::SignatureMismatch)));
                session.info().unwrap();
                if fault == 0 {
                    signature[0] = 0xAB;
                    session
                        .verify_ml_dsa_signature_first(
                            &key(),
                            &parameters(0).request(b"abc"),
                            &signature,
                        )
                        .unwrap();
                }
            },
        );
    }
}
#[test]
fn errors_and_abandoned_verification_discard_without_fallback_or_cancellation() {
    for fault in [
        0, 11, 12, 13, 14, 15, 18, 21, 22, 26, 29, 30, 31, 32, 33, 34,
    ] {
        with_fixture(
            MlDsaVerifyModule::new(3, 2, fault, 0, 1, 0),
            ModuleOptions::default(),
            |_, session, watcher| {
                let signature = vec![0xAB; 2420];
                if matches!(fault, 18 | 32) {
                    assert!(
                        session
                            .verify_ml_dsa_signature_first(
                                &key(),
                                &parameters(0).request(b"abc"),
                                &signature
                            )
                            .is_err()
                    );
                } else {
                    match session.start_ml_dsa_verification(&key(), parameters(0), &signature) {
                        Err(_) => assert!(matches!(fault, 11 | 12 | 29 | 31)),
                        Ok(mut operation) => match fault {
                            0 => drop(operation),
                            13 | 14 | 21 | 22 | 33 => {
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
                }
                assert!(session.info().is_err());
                let calls = watcher.info().unwrap().device_error();
                assert_eq!(calls >> 24, 1);
                assert_eq!(calls & 0xF, 0);
                assert_eq!(
                    calls >> 4 & 0xF,
                    u64::from(matches!(fault, 15 | 26 | 30 | 34))
                );
            },
        );
    }
}
#[test]
fn operation_specific_cancellation_confirms_termination_without_session_cancel() {
    for fault in [0, 19, 20, 25] {
        with_fixture(
            MlDsaVerifyModule::new(3, 2, fault, 0, 1, 0),
            ModuleOptions::default(),
            |_, session, watcher| {
                let signature = vec![0xAB; 2420];
                let mut operation = session
                    .start_ml_dsa_verification(&key(), parameters(0), &signature)
                    .unwrap();
                operation.update(b"a").unwrap();
                let result = operation.cancel();
                if matches!(fault, 0 | 20) {
                    result.unwrap();
                    session.info().unwrap();
                    session
                        .verify_ml_dsa_signature_first(
                            &key(),
                            &parameters(0).request(b"abc"),
                            &signature,
                        )
                        .unwrap();
                } else {
                    assert!(result.is_err());
                    assert!(session.info().is_err());
                }
                assert_eq!(watcher.info().unwrap().device_error() & 0xF, 1);
            },
        );
    }
}
