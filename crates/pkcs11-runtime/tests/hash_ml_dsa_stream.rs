// SPDX-License-Identifier: MIT OR Apache-2.0
//! HashML-DSA multipart parameters, independent pointer gates and lifecycle.
#![cfg(unix)]
#[path = "fixtures/hash_ml_dsa_module.rs"]
mod fixture;
use fixture::HashMlDsaModule;
use pkcs11_runtime::*;
use secrecy::SecretString;
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
fn selected_tables_all_sets_contexts_hedging_and_independent_multipart_pointers() {
    for (major, minor) in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        for (index, parameter_set) in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ]
        .into_iter()
        .enumerate()
        {
            for (hedge, context_length, auth) in [(0, 0, 0), (1, 255, 1), (2, 1, 0)] {
                for verify in [false, true] {
                    // The single-part completion pointer is absent, but multipart is usable.
                    let fixture = HashMlDsaModule::streaming(
                        major,
                        minor,
                        if verify { 10 } else { 8 },
                        index as u8,
                        hedge,
                        context_length,
                        auth,
                        verify,
                    );
                    let module = Module::load(fixture.path()).unwrap();
                    let token = module
                        .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                        .unwrap();
                    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                    let pin = SecretString::from("1234");
                    let context = vec![0xA5; context_length];
                    let p = HashMlDsaParameters {
                        parameter_set,
                        context: &context,
                        hedging: match hedge {
                            0 => MlDsaHedging::Preferred,
                            1 => MlDsaHedging::Required,
                            _ => MlDsaHedging::Deterministic,
                        },
                    };
                    for message in [&[][..], b"abc"] {
                        if verify {
                            let caps = session
                                .hash_ml_dsa_verification_capabilities(&public())
                                .unwrap();
                            assert!(!caps.can_verify && caps.can_stream);
                            let mut operation = session
                                .start_hash_ml_dsa_verification(&public(), p)
                                .unwrap();
                            assert_eq!(operation.parameter_set(), parameter_set);
                            for chunk in message.chunks(1) {
                                operation.update(chunk).unwrap();
                            }
                            operation
                                .finish(&vec![0xAB; parameter_set.signature_length()])
                                .unwrap();
                        } else {
                            assert!(
                                !session
                                    .hash_ml_dsa_capabilities(&private(), HashMlDsaMode::Message)
                                    .unwrap()
                                    .can_sign
                            );
                            assert!(
                                session
                                    .hash_ml_dsa_streaming_capabilities(&private())
                                    .unwrap()
                                    .can_sign
                            );
                            let mut operation = session
                                .start_hash_ml_dsa_signing(
                                    &private(),
                                    p,
                                    &MlDsaSigningPolicy::default(),
                                    (auth != 0).then_some(Pin::Value(&pin)),
                                )
                                .unwrap();
                            for chunk in message.chunks(1) {
                                operation.update(chunk).unwrap();
                            }
                            assert_eq!(
                                operation.finish().unwrap(),
                                vec![0xAB; parameter_set.signature_length()]
                            );
                        }
                        session.info().unwrap();
                    }
                    session.close().unwrap();
                    drop(token);
                    module.finalize().unwrap();
                }
            }
        }
    }
}
#[test]
fn preflight_permissions_and_missing_multipart_pointers_reject_before_init() {
    for verify in [false, true] {
        for fault in [0, 1, 2, 3, 4, 5, 6, 7, 9, 25, 26, 35, 36] {
            if (verify && [6, 7].contains(&fault)) || (!verify && fault == 9) {
                continue;
            }
            let fixture = HashMlDsaModule::streaming(3, 2, fault, 0, 1, 0, 1, verify);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let pin = SecretString::from("1234");
            let p = if fault == 0 {
                HashMlDsaParameters {
                    context: &[0; 256],
                    ..parameters()
                }
            } else {
                parameters()
            };
            if verify {
                assert!(
                    session
                        .start_hash_ml_dsa_verification(&public(), p)
                        .is_err()
                );
            } else {
                assert!(
                    session
                        .start_hash_ml_dsa_signing(
                            &private(),
                            p,
                            &MlDsaSigningPolicy::default(),
                            Some(Pin::Value(&pin))
                        )
                        .is_err()
                );
            }
            assert_eq!(session.info().unwrap().device_error(), 0);
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn native_init_update_final_errors_malformed_output_and_drop_discard() {
    for verify in [false, true] {
        let faults = if verify {
            vec![0, 11, 18, 21, 22, 27, 28, 29, 30]
        } else {
            vec![0, 11, 12, 13, 14, 15, 16, 17, 22, 27, 28, 29, 30]
        };
        for fault in faults {
            let fixture = HashMlDsaModule::streaming(3, 2, fault, 0, 1, 0, 1, verify);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let pin = SecretString::from("1234");
            if verify {
                match session.start_hash_ml_dsa_verification(&public(), parameters()) {
                    Err(_) => assert!([11, 22].contains(&fault)),
                    Ok(mut operation) => {
                        if fault == 0 {
                            drop(operation);
                        } else if [27, 28, 29, 30].contains(&fault) {
                            assert!(operation.update(b"a").is_err());
                            assert!(matches!(operation.update(b"b"), Err(Error::Closed)));
                            assert!(operation.finish(&[0xAB; 2420]).is_err());
                        } else {
                            operation.update(b"abc").unwrap();
                            assert!(operation.finish(&[0xAB; 2420]).is_err());
                        }
                    }
                }
            } else {
                match session.start_hash_ml_dsa_signing(
                    &private(),
                    parameters(),
                    &MlDsaSigningPolicy::default(),
                    Some(Pin::Value(&pin)),
                ) {
                    Err(_) => assert!([11, 12, 22].contains(&fault)),
                    Ok(mut operation) => {
                        if fault == 0 {
                            drop(operation);
                        } else if [27, 28, 29, 30].contains(&fault) {
                            assert!(operation.update(b"a").is_err());
                            assert!(matches!(operation.update(b"b"), Err(Error::Closed)));
                            assert!(operation.finish().is_err());
                        } else {
                            operation.update(b"abc").unwrap();
                            assert!(operation.finish().is_err());
                        }
                    }
                }
            }
            assert!(session.info().is_err());
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn completed_mismatches_reuse_but_malformed_signature_lengths_discard_active_streams() {
    for fault in [0, 19, 20] {
        let fixture = HashMlDsaModule::streaming(3, 2, fault, 0, 1, 0, 0, true);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        for _ in 0..2 {
            let mut operation = session
                .start_hash_ml_dsa_verification(&public(), parameters())
                .unwrap();
            operation.update(b"abc").unwrap();
            assert!(matches!(
                operation.finish(&[0; 2420]),
                Err(Error::SignatureMismatch)
            ));
            session.info().unwrap();
        }
        let operation = session
            .start_hash_ml_dsa_verification(&public(), parameters())
            .unwrap();
        assert!(matches!(
            operation.finish(&[0; 2419]),
            Err(Error::SignatureMismatch)
        ));
        assert!(session.info().is_err());
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
#[test]
fn cancellation_checks_selected_interface_flags_and_failed_termination() {
    for (major, minor, fault) in [
        (2, 40, 0),
        (3, 0, 0),
        (3, 1, 0),
        (3, 2, 0),
        (3, 2, 31),
        (3, 2, 32),
        (3, 2, 33),
    ] {
        for verify in [false, true] {
            let fixture = HashMlDsaModule::streaming(major, minor, fault, 0, 1, 0, 0, verify);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let result = if verify {
                let mut op = session
                    .start_hash_ml_dsa_verification(&public(), parameters())
                    .unwrap();
                op.update(b"a").unwrap();
                op.cancel()
            } else {
                let mut op = session
                    .start_hash_ml_dsa_signing(
                        &private(),
                        parameters(),
                        &MlDsaSigningPolicy::default(),
                        None,
                    )
                    .unwrap();
                op.update(b"a").unwrap();
                op.cancel()
            };
            if major >= 3 && fault == 0 {
                result.unwrap();
                session.info().unwrap();
            } else {
                assert!(result.is_err());
                assert!(session.info().is_err());
            }
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
