// SPDX-License-Identifier: MIT OR Apache-2.0
//! HashSLH-DSA message/digest ABIs, exact allocation and failure lifecycle.
#![cfg(unix)]
#[path = "fixtures/slh_dsa_module.rs"]
mod fixture;
use pkcs11_runtime::*;
use secrecy::SecretString;
fn private() -> PrivateKeyRef {
    PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap()
}
fn public() -> PublicKeyRef {
    PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap()
}
fn request<'a>(
    parameter_set: SlhDsaParameterSet,
    hedging: SlhDsaHedging,
    context: &'a [u8],
    input: HashSlhDsaInput<'a>,
) -> HashSlhDsaRequest<'a> {
    HashSlhDsaRequest {
        parameter_set,
        hedging,
        context,
        input,
    }
}
#[test]
fn all_fixed_hash_modes_tables_hedges_contexts_and_authentication_order() {
    for table in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        for (hash_index, hash) in HashSlhDsaSigningPolicy::default()
            .hashes
            .into_iter()
            .enumerate()
        {
            for prehashed in [false, true] {
                let index = (hash_index * 2 + usize::from(prehashed)) % 12;
                let parameter = SlhDsaParameterSet::ALL[index];
                let (hedge, hedging, length) = match index % 3 {
                    0 => (0, SlhDsaHedging::Preferred, 0),
                    1 => (1, SlhDsaHedging::Required, 255),
                    _ => (2, SlhDsaHedging::Deterministic, 3),
                };
                let auth = index % 2 == 1;
                let fixture = fixture::SlhDsaModule::hash(
                    table,
                    index,
                    0,
                    auth,
                    (hedge, length),
                    (hash_index, prehashed),
                );
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                let pin = SecretString::from("12345678");
                let context = vec![0xa5; length];
                let digest = vec![0xc7; hash.output_len()];
                let input = if prehashed {
                    HashSlhDsaInput::Digest {
                        hash,
                        bytes: &digest,
                    }
                } else {
                    HashSlhDsaInput::Message {
                        hash,
                        message: b"abc",
                    }
                };
                let request = request(parameter, hedging, &context, input);
                let signature = session
                    .sign_hash_slh_dsa(
                        &private(),
                        &request,
                        &HashSlhDsaSigningPolicy {
                            allow_reduced_strength: true,
                            ..Default::default()
                        },
                        auth.then_some(Pin::Value(&pin)),
                    )
                    .unwrap();
                assert_eq!(signature, vec![0xab; parameter.signature_length()]);
                assert_eq!(
                    session.info().unwrap().device_error(),
                    (1 << 16) | ((u64::from(auth)) << 8) | 1
                );
                session
                    .verify_hash_slh_dsa(&public(), &request, &signature)
                    .unwrap();
                let mut bad = signature;
                bad[0] ^= 1;
                assert!(matches!(
                    session.verify_hash_slh_dsa(&public(), &request, &bad),
                    Err(Error::SignatureMismatch)
                ));
                session.info().unwrap();
                assert!(session.slh_dsa_public_key(&public()).is_err());
                session.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
#[test]
fn unsupported_flags_pointers_policy_native_failures_and_reusable_mismatches() {
    for table in [(2, 40), (3, 2)] {
        for fault in 1..=25 {
            let fixture = fixture::SlhDsaModule::hash(table, 0, fault, true, (1, 3), (3, true));
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let pin = SecretString::from("12345678");
            let request = request(
                SlhDsaParameterSet::Sha2_128S,
                SlhDsaHedging::Required,
                &[0xa5; 3],
                HashSlhDsaInput::Digest {
                    hash: DigestAlgorithm::Sha512,
                    bytes: &[0xc7; 64],
                },
            );
            for verify in [false, true] {
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                let result = if verify {
                    session.verify_hash_slh_dsa(
                        &public(),
                        &request,
                        &vec![0xab; request.parameter_set.signature_length()],
                    )
                } else {
                    session
                        .sign_hash_slh_dsa(
                            &private(),
                            &request,
                            &HashSlhDsaSigningPolicy {
                                allow_reduced_strength: true,
                                ..Default::default()
                            },
                            Some(Pin::Value(&pin)),
                        )
                        .map(|_| ())
                };
                let preflight = matches!(fault,1..=4|11..=14)
                    || if verify {
                        matches!(fault, 7 | 8 | 10)
                    } else {
                        matches!(fault, 5 | 6 | 9)
                    };
                let preflight = preflight || (!verify && fault == 15);
                let native = if verify {
                    matches!(fault, 16 | 24 | 25)
                } else {
                    matches!(fault, 16..=21)
                };
                let mismatch = verify && matches!(fault, 22 | 23);
                if mismatch {
                    assert!(matches!(result, Err(Error::SignatureMismatch)));
                } else {
                    assert_eq!(
                        result.is_err(),
                        preflight || native,
                        "{table:?}/{fault}/{verify}: {result:?}"
                    );
                }
                assert_eq!(
                    session.info().is_err(),
                    native,
                    "{table:?}/{fault}/{verify}"
                );
                if preflight {
                    assert_eq!(session.info().unwrap().device_error(), 0);
                }
                session.close().unwrap();
            }
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn hash_generation_templates_bounds_duplicates() {
    for (index, parameter_set) in SlhDsaParameterSet::ALL.into_iter().enumerate() {
        let fixture = fixture::SlhDsaModule::hash((3, 2), index, 100, false, (0, 0), (0, false));
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        assert!(
            token
                .slh_dsa_generation_options()
                .unwrap()
                .contains(&parameter_set)
        );
        let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
        let generation = SlhDsaKeyPairRequest {
            parameter_set,
            id: &[1],
            label: b"x",
            always_authenticate: false,
        };
        session.generate_hash_slh_dsa_key_pair(&generation).unwrap();
        assert!(matches!(
            session.generate_hash_slh_dsa_key_pair(&generation),
            Err(Error::InvalidParameters(_))
        ));
        assert_eq!(session.info().unwrap().device_error(), 1 << 24);
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
    for fault in [101, 103, 104, 128, 129, 130, 131] {
        let fixture = fixture::SlhDsaModule::hash((3, 2), 0, fault, false, (0, 0), (0, false));
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
        assert!(
            session
                .generate_hash_slh_dsa_key_pair(&SlhDsaKeyPairRequest {
                    parameter_set: SlhDsaParameterSet::Sha2_128S,
                    id: &[1],
                    label: b"x",
                    always_authenticate: false
                })
                .is_err()
        );
        assert_eq!(session.info().is_err(), fault == 129);
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}

#[test]
fn pin_input_and_policy_errors_do_not_initialize_signing() {
    for auth in [false, true] {
        let fixture = fixture::SlhDsaModule::hash((3, 2), 0, 0, auth, (1, 0), (3, true));
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let request = HashSlhDsaRequest {
            parameter_set: SlhDsaParameterSet::Sha2_128S,
            input: HashSlhDsaInput::Digest {
                hash: DigestAlgorithm::Sha512,
                bytes: &[0xc7; 64],
            },
            context: &[],
            hedging: SlhDsaHedging::Required,
        };
        let pin = SecretString::from("12345678");
        let bad_pin = (!auth).then_some(Pin::Value(&pin));
        assert!(
            session
                .sign_hash_slh_dsa(
                    &private(),
                    &request,
                    &HashSlhDsaSigningPolicy::default(),
                    bad_pin
                )
                .is_err()
        );
        let invalid = HashSlhDsaRequest {
            input: HashSlhDsaInput::Digest {
                hash: DigestAlgorithm::Sha512,
                bytes: &[0; 63],
            },
            ..request
        };
        assert!(
            session
                .sign_hash_slh_dsa(
                    &private(),
                    &invalid,
                    &HashSlhDsaSigningPolicy::default(),
                    None
                )
                .is_err()
        );
        let weak = HashSlhDsaRequest {
            input: HashSlhDsaInput::Digest {
                hash: DigestAlgorithm::Sha224,
                bytes: &[0; 28],
            },
            ..request
        };
        assert!(
            session
                .sign_hash_slh_dsa(&private(), &weak, &HashSlhDsaSigningPolicy::default(), None)
                .is_err()
        );
        assert_eq!(session.info().unwrap().device_error(), 0);
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
