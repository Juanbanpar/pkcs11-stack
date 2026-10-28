// SPDX-License-Identifier: MIT OR Apache-2.0
//! Streaming signature parameters, authentication, pointer gates and session health.
#![cfg(unix)]
#[path = "fixtures/signature_stream_module.rs"]
mod fixture;
use fixture::SignatureStreamModule;
use pkcs11_runtime::*;
use secrecy::SecretString;
fn private() -> PrivateKeyRef {
    PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap()
}
fn public() -> PublicKeyRef {
    PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap()
}
fn parameters(algorithm: SignatureAlgorithm, digest: DigestAlgorithm) -> SignatureParameters {
    SignatureParameters {
        algorithm,
        digest,
        pss: (algorithm == SignatureAlgorithm::RsaPss).then_some(PssParameters {
            mgf_digest: DigestAlgorithm::Sha384,
            salt_len: 20,
        }),
    }
}
fn policy(hashing: HashingPolicy, digest: DigestAlgorithm) -> SigningPolicy {
    let mut policy = SigningPolicy {
        hashing,
        ..Default::default()
    };
    if !policy.digests.contains(&digest) {
        policy.digests.push(digest);
    }
    policy
}
#[test]
fn parameters_inputs_context_authentication_and_completion_across_versions() {
    for (major, minor) in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        for curve in 0..=3 {
            let fixture = SignatureStreamModule::new(major, minor, 0, curve, false, 224, 1);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let pin = SecretString::from("1234");
            let algorithms: &[SignatureAlgorithm] = if curve == 0 {
                &[SignatureAlgorithm::RsaPkcs1, SignatureAlgorithm::RsaPss]
            } else {
                &[SignatureAlgorithm::Ecdsa]
            };
            for &algorithm in algorithms {
                for hashing in [
                    HashingPolicy::TokenOnly,
                    HashingPolicy::AllowSoftware,
                    HashingPolicy::SoftwareOnly,
                ] {
                    let policy = policy(hashing, DigestAlgorithm::Sha224);
                    let parameters = parameters(algorithm, DigestAlgorithm::Sha224);
                    assert!(matches!(
                        session.start_signing(&private(), parameters, &policy, None),
                        Err(Error::ContextAuthenticationRequired)
                    ));
                    let mut operation = session
                        .start_signing(&private(), parameters, &policy, Some(Pin::Value(&pin)))
                        .unwrap();
                    assert_eq!(
                        operation.plan().hash_location(),
                        if hashing == HashingPolicy::SoftwareOnly {
                            HashLocation::Software
                        } else {
                            HashLocation::Token
                        }
                    );
                    assert!(operation.plan().context_authentication());
                    operation.update(b"").unwrap();
                    operation.update(b"a").unwrap();
                    operation.update(b"bc").unwrap();
                    assert!(!format!("{operation:?}").contains("1234"));
                    let signature = operation.finish().unwrap();
                    assert_eq!(
                        signature,
                        vec![
                            0xAB;
                            match curve {
                                0 => 256,
                                1 => 64,
                                2 => 96,
                                _ => 132,
                            }
                        ]
                    );
                    session.info().unwrap();
                    for supplied in [
                        signature.clone(),
                        vec![],
                        vec![0; signature.len()],
                        vec![0xAB; signature.len() - 1],
                    ] {
                        let mut operation = session
                            .start_verification(&public(), parameters, &policy)
                            .unwrap();
                        operation.update(b"ab").unwrap();
                        operation.update(b"c").unwrap();
                        let result = operation.finish(&supplied);
                        if supplied == signature {
                            result.unwrap();
                        } else {
                            assert!(matches!(result, Err(Error::SignatureMismatch)));
                        }
                        session.info().unwrap();
                    }
                }
            }
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn all_sha3_digest_encodings_and_explicit_pss_parameters() {
    for (bits, digest) in [
        (224, DigestAlgorithm::Sha3_224),
        (256, DigestAlgorithm::Sha3_256),
        (384, DigestAlgorithm::Sha3_384),
        (512, DigestAlgorithm::Sha3_512),
    ] {
        for curve in [0, 1] {
            let fixture = SignatureStreamModule::new(3, 0, 0, curve, true, bits, 0);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            for algorithm in if curve == 0 {
                vec![SignatureAlgorithm::RsaPkcs1, SignatureAlgorithm::RsaPss]
            } else {
                vec![SignatureAlgorithm::Ecdsa]
            } {
                for hashing in [HashingPolicy::TokenOnly, HashingPolicy::SoftwareOnly] {
                    let mut parameters = parameters(algorithm, digest);
                    // The SHA-3 encoding fixture uses a different, explicit MGF.
                    if let Some(pss) = &mut parameters.pss {
                        pss.mgf_digest = match bits {
                            224 => DigestAlgorithm::Sha3_256,
                            256 => DigestAlgorithm::Sha3_384,
                            384 => DigestAlgorithm::Sha3_512,
                            _ => DigestAlgorithm::Sha3_224,
                        };
                    }
                    let mut policy = policy(hashing, digest);
                    policy.digests.extend([
                        DigestAlgorithm::Sha3_224,
                        DigestAlgorithm::Sha3_256,
                        DigestAlgorithm::Sha3_384,
                        DigestAlgorithm::Sha3_512,
                    ]);
                    assert!(
                        session
                            .start_signing(&private(), parameters, &SigningPolicy::default(), None)
                            .is_err()
                    );
                    let mut operation = session
                        .start_signing(&private(), parameters, &policy, None)
                        .unwrap();
                    operation.update(b"a").unwrap();
                    operation.update(b"bc").unwrap();
                    let signature = operation.finish().unwrap();
                    let mut operation = session
                        .start_verification(&public(), parameters, &policy)
                        .unwrap();
                    operation.update(b"abc").unwrap();
                    operation.finish(&signature).unwrap();
                }
            }
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn pointer_and_permission_gates_respect_hashing_policy_before_initialization() {
    for fault in [31, 32, 33, 34, 35, 36, 37, 38, 40, 41, 42, 43, 44, 48] {
        for verification in [false, true] {
            let fixture = SignatureStreamModule::new(2, 40, fault, 0, false, 224, 0);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let parameters = parameters(SignatureAlgorithm::RsaPkcs1, DigestAlgorithm::Sha224);
            for hashing in [
                HashingPolicy::TokenOnly,
                HashingPolicy::AllowSoftware,
                HashingPolicy::SoftwareOnly,
            ] {
                let policy = policy(hashing, DigestAlgorithm::Sha224);
                let denied = if fault == 48 {
                    true
                } else if verification {
                    matches!(fault, 38 | 41 | 44)
                        || (hashing == HashingPolicy::TokenOnly && matches!(fault, 33 | 34 | 42))
                        || (hashing == HashingPolicy::SoftwareOnly && fault == 36)
                } else {
                    matches!(fault, 37 | 40 | 43)
                        || (hashing == HashingPolicy::TokenOnly && matches!(fault, 31 | 32 | 42))
                        || (hashing == HashingPolicy::SoftwareOnly && fault == 35)
                };
                if verification {
                    match session.start_verification(&public(), parameters, &policy) {
                        Err(error) => assert!(
                            denied && matches!(error, Error::UnsupportedVerification(_)),
                            "fault={fault}, hashing={hashing:?}, {error:?}"
                        ),
                        Ok(mut operation) => {
                            assert!(!denied);
                            operation.update(b"abc").unwrap();
                            operation.finish(&[0xAB; 256]).unwrap();
                        }
                    }
                } else {
                    match session.start_signing(&private(), parameters, &policy, None) {
                        Err(error) => assert!(
                            denied && matches!(error, Error::UnsupportedSigning(_)),
                            "fault={fault}, hashing={hashing:?}, {error:?}"
                        ),
                        Ok(mut operation) => {
                            assert!(!denied);
                            operation.update(b"abc").unwrap();
                            operation.finish().unwrap();
                        }
                    }
                }
                session.info().unwrap();
            }
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn abandoned_failed_and_malformed_operations_are_never_reused() {
    for verification in [false, true] {
        for hashing in [
            HashingPolicy::TokenOnly,
            HashingPolicy::AllowSoftware,
            HashingPolicy::SoftwareOnly,
        ] {
            for fault in [0, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28] {
                if verification && matches!(fault, 22 | 26 | 27 | 28)
                    || hashing == HashingPolicy::SoftwareOnly && matches!(fault, 23 | 24)
                {
                    continue;
                }
                let fixture = SignatureStreamModule::new(3, 2, fault, 0, false, 224, 1);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                let pin = SecretString::from("1234");
                let policy = policy(hashing, DigestAlgorithm::Sha224);
                let parameters = parameters(SignatureAlgorithm::RsaPkcs1, DigestAlgorithm::Sha224);
                if verification {
                    match session.start_verification(&public(), parameters, &policy) {
                        Err(_) => assert!(matches!(fault, 20 | 21)),
                        Ok(mut operation) => match fault {
                            0 | 19 => {
                                if fault == 0 {
                                    operation.update(b"a").unwrap();
                                }
                                drop(operation);
                            }
                            23 | 24 => {
                                assert!(operation.update(b"abc").is_err());
                                assert!(matches!(operation.update(b"retry"), Err(Error::Closed)));
                                assert!(matches!(operation.cancel(), Err(Error::Closed)));
                            }
                            _ => {
                                operation.update(b"abc").unwrap();
                                assert!(operation.finish(&[0xAB; 256]).is_err());
                            }
                        },
                    }
                } else {
                    match session.start_signing(
                        &private(),
                        parameters,
                        &policy,
                        Some(Pin::Value(&pin)),
                    ) {
                        Err(_) => assert!(matches!(fault, 20..=22)),
                        Ok(mut operation) => match fault {
                            0 | 19 => {
                                if fault == 0 {
                                    operation.update(b"a").unwrap();
                                }
                                drop(operation);
                            }
                            23 | 24 => {
                                assert!(operation.update(b"abc").is_err());
                                assert!(matches!(operation.update(b"retry"), Err(Error::Closed)));
                                assert!(matches!(operation.finish(), Err(Error::Closed)));
                            }
                            _ => {
                                operation.update(b"abc").unwrap();
                                assert!(operation.finish().is_err());
                            }
                        },
                    }
                }
                assert!(matches!(session.info(), Err(Error::Closed)));
                let calls = watcher.info().unwrap().device_error();
                assert_eq!(calls >> 24, 1);
                assert_eq!(calls & 0xF, 0, "no implicit cancellation");
                assert_eq!(calls >> 4 & 0xF, u64::from(matches!(fault, 25..=28)));
                session.close().unwrap();
                watcher.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
#[test]
fn protected_path_wrong_pin_and_completed_verification_mismatches() {
    for fault in [0, 29, 30] {
        let fixture = SignatureStreamModule::new(3, 2, fault, 0, false, 224, 2);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let parameters = parameters(SignatureAlgorithm::RsaPkcs1, DigestAlgorithm::Sha224);
        let policy = policy(HashingPolicy::TokenOnly, DigestAlgorithm::Sha224);
        let mut operation = session
            .start_signing(&private(), parameters, &policy, Some(Pin::ProtectedPath))
            .unwrap();
        operation.update(b"abc").unwrap();
        let signature = operation.finish().unwrap();
        let mut operation = session
            .start_verification(&public(), parameters, &policy)
            .unwrap();
        operation.update(b"abc").unwrap();
        let result = operation.finish(&signature);
        if fault == 0 {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(Error::SignatureMismatch)));
        }
        session.info().unwrap();
        let wrong = SecretString::from("PIN-canary");
        assert!(
            session
                .start_signing(&private(), parameters, &policy, Some(Pin::Value(&wrong)))
                .is_err()
        );
        assert!(session.info().is_err());
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
#[test]
fn explicit_cancellation_confirms_native_state_for_both_hashing_paths() {
    for (major, minor, fault) in [(2, 40, 0), (3, 0, 0), (3, 1, 0), (3, 2, 0), (3, 2, 39)] {
        for hashing in [HashingPolicy::TokenOnly, HashingPolicy::SoftwareOnly] {
            for verification in [false, true] {
                let fixture = SignatureStreamModule::new(major, minor, fault, 0, false, 224, 0);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                let parameters = parameters(SignatureAlgorithm::RsaPkcs1, DigestAlgorithm::Sha224);
                let policy = policy(hashing, DigestAlgorithm::Sha224);
                let result = if verification {
                    let mut operation = session
                        .start_verification(&public(), parameters, &policy)
                        .unwrap();
                    operation.update(b"a").unwrap();
                    operation.cancel()
                } else {
                    let mut operation = session
                        .start_signing(&private(), parameters, &policy, None)
                        .unwrap();
                    operation.update(b"a").unwrap();
                    operation.cancel()
                };
                if major >= 3 && fault == 0 {
                    result.unwrap();
                    session.info().unwrap();
                    let mut operation = session
                        .start_signing(&private(), parameters, &policy, None)
                        .unwrap();
                    operation.update(b"abc").unwrap();
                    operation.finish().unwrap();
                } else {
                    assert!(result.is_err());
                    assert!(session.info().is_err());
                }
                assert_eq!(
                    watcher.info().unwrap().device_error() & 0xF,
                    u64::from(major >= 3)
                );
                session.close().unwrap();
                watcher.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
