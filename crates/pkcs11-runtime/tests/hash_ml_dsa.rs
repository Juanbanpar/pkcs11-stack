// SPDX-License-Identifier: MIT OR Apache-2.0
//! Official HashML-DSA ABI, exact input contracts and failed-session handling.
#![cfg(unix)]
#[path = "fixtures/hash_ml_dsa_module.rs"]
mod fixture;
use fixture::HashMlDsaModule;
use pkcs11_runtime::*;
use secrecy::SecretString;
const SETS: [MlDsaParameterSet; 3] = [
    MlDsaParameterSet::MlDsa44,
    MlDsaParameterSet::MlDsa65,
    MlDsaParameterSet::MlDsa87,
];
fn private() -> PrivateKeyRef {
    PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap()
}
fn public() -> PublicKeyRef {
    PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap()
}
fn request(prehash: bool) -> HashMlDsaRequest<'static> {
    HashMlDsaRequest {
        parameter_set: SETS[0],
        input: if prehash {
            HashMlDsaInput::Sha512Digest(&[0xA5; 64])
        } else {
            HashMlDsaInput::Message(b"abc")
        },
        context: &[],
        hedging: MlDsaHedging::Required,
    }
}
#[test]
fn parameters_contexts_hedging_and_single_part_authentication_on_all_tables() {
    for (major, minor) in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        for prehash in [false, true] {
            for parameter in 0..3 {
                for (hedge, context_length, auth) in [(0, 0, 0), (1, 255, 1), (2, 1, 0)] {
                    let fixture = HashMlDsaModule::new(
                        major,
                        minor,
                        0,
                        parameter,
                        hedge,
                        context_length,
                        auth,
                        prehash,
                        false,
                    );
                    let module = Module::load(fixture.path()).unwrap();
                    let token = module
                        .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                        .unwrap();
                    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                    let context = vec![0xA5; context_length];
                    let request = HashMlDsaRequest {
                        parameter_set: SETS[usize::from(parameter)],
                        context: &context,
                        hedging: match hedge {
                            0 => MlDsaHedging::Preferred,
                            1 => MlDsaHedging::Required,
                            _ => MlDsaHedging::Deterministic,
                        },
                        ..request(prehash)
                    };
                    assert!(!format!("{request:?}").contains("abc"));
                    assert!(!format!("{:?}", request.input).contains("165"));
                    let caps = session
                        .hash_ml_dsa_capabilities(&private(), request.input.mode())
                        .unwrap();
                    assert!(caps.can_sign);
                    assert_eq!(caps.always_authenticate, auth != 0);
                    assert!(
                        !session
                            .hash_ml_dsa_capabilities(
                                &private(),
                                if prehash {
                                    HashMlDsaMode::Message
                                } else {
                                    HashMlDsaMode::Prehashed
                                }
                            )
                            .unwrap()
                            .can_sign
                    );
                    let pin = SecretString::from("1234");
                    let sig = session
                        .sign_hash_ml_dsa(
                            &private(),
                            &request,
                            &MlDsaSigningPolicy::default(),
                            (auth != 0).then_some(Pin::Value(&pin)),
                        )
                        .unwrap();
                    assert_eq!(sig, vec![0xAB; request.parameter_set.signature_length()]);
                    assert_eq!(
                        session.info().unwrap().device_error(),
                        (1 << 16) | (u64::from(auth) << 8) | 1
                    );
                    session.close().unwrap();
                    drop(token);
                    module.finalize().unwrap();
                }
            }
        }
    }
}
#[test]
fn policy_context_key_permissions_and_pointer_gates_reject_before_init() {
    for prehash in [false, true] {
        for verify in [false, true] {
            let faults = if verify {
                vec![0, 1, 2, 3, 4, 5, 9, 10, 25, 26]
            } else {
                vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 25, 26]
            };
            for fault in faults {
                let fixture = HashMlDsaModule::new(3, 2, fault, 0, 1, 0, 1, prehash, verify);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                let request = request(prehash);
                let pin = SecretString::from("1234");
                let policy = MlDsaSigningPolicy::default();
                if fault == 0 {
                    let too_long = HashMlDsaRequest {
                        context: &[0; 256],
                        ..request
                    };
                    if verify {
                        assert!(
                            session
                                .verify_hash_ml_dsa(&public(), &too_long, &vec![0xAB; 2420])
                                .is_err()
                        );
                    } else {
                        assert!(
                            session
                                .sign_hash_ml_dsa(
                                    &private(),
                                    &too_long,
                                    &policy,
                                    Some(Pin::Value(&pin))
                                )
                                .is_err()
                        );
                        assert!(
                            session
                                .sign_hash_ml_dsa(
                                    &private(),
                                    &request,
                                    &MlDsaSigningPolicy {
                                        parameter_sets: vec![]
                                    },
                                    Some(Pin::Value(&pin))
                                )
                                .is_err()
                        );
                        assert!(matches!(
                            session.sign_hash_ml_dsa(&private(), &request, &policy, None),
                            Err(Error::ContextAuthenticationRequired)
                        ));
                    }
                } else if verify {
                    assert!(
                        session
                            .verify_hash_ml_dsa(&public(), &request, &vec![0xAB; 2420])
                            .is_err()
                    );
                } else {
                    assert!(
                        session
                            .sign_hash_ml_dsa(&private(), &request, &policy, Some(Pin::Value(&pin)))
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
}
#[test]
fn native_errors_short_and_oversized_output_discard_without_retry() {
    for prehash in [false, true] {
        for (verify, faults) in [
            (false, vec![11, 12, 13, 14, 15, 16, 17, 22]),
            (true, vec![11, 18, 21, 22]),
        ] {
            for fault in faults {
                let fixture = HashMlDsaModule::new(3, 2, fault, 0, 1, 0, 1, prehash, verify);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                let request = request(prehash);
                let pin = SecretString::from("1234");
                if verify {
                    assert!(
                        session
                            .verify_hash_ml_dsa(&public(), &request, &vec![0xAB; 2420])
                            .is_err()
                    );
                } else {
                    assert!(
                        session
                            .sign_hash_ml_dsa(
                                &private(),
                                &request,
                                &MlDsaSigningPolicy::default(),
                                Some(Pin::Value(&pin))
                            )
                            .is_err()
                    );
                }
                assert!(session.info().is_err());
                let calls = watcher.info().unwrap().device_error();
                assert_eq!(calls >> 16, 1);
                assert!(calls & 255 <= 1);
                session.close().unwrap();
                watcher.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
#[test]
fn only_completed_verification_mismatches_preserve_reuse() {
    for prehash in [false, true] {
        for fault in [0, 19, 20] {
            let fixture = HashMlDsaModule::new(3, 2, fault, 0, 1, 0, 0, prehash, true);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let request = request(prehash);
            assert!(matches!(
                session.verify_hash_ml_dsa(&public(), &request, &[0; 2420]),
                Err(Error::SignatureMismatch)
            ));
            assert!(matches!(
                session.verify_hash_ml_dsa(&public(), &request, &[0; 2419]),
                Err(Error::SignatureMismatch)
            ));
            let valid = vec![0xAB; 2420];
            for _ in 0..2 {
                let result = session.verify_hash_ml_dsa(&public(), &request, &valid);
                if fault == 0 {
                    result.unwrap();
                } else {
                    assert!(matches!(result, Err(Error::SignatureMismatch)));
                }
                session.info().unwrap();
            }
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
