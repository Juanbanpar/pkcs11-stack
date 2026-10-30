// SPDX-License-Identifier: MIT OR Apache-2.0
//! Client policy preflight, completed mismatch mapping and session pool reuse.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/hash_ml_dsa_module.rs"]
mod fixture;
use fixture::HashMlDsaModule;
use pkcs11_client::*;
use std::num::NonZeroUsize;
fn private() -> PrivateKeyRef {
    PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap()
}
fn public() -> PublicKeyRef {
    PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap()
}
#[test]
fn hash_ml_dsa_client_single_part_signing_and_completed_mismatch_reuse() {
    for prehash in [false, true] {
        for verify in [false, true] {
            let fixture = HashMlDsaModule::new(3, 2, 0, 0, 1, 0, 0, prehash, verify);
            let provider = Provider::load(fixture.path()).unwrap();
            let client = provider
                .client(
                    &"pkcs11:token=cmac".parse().unwrap(),
                    NonZeroUsize::new(1).unwrap(),
                    SigningPolicy::default(),
                )
                .unwrap();
            let request = HashMlDsaRequest {
                parameter_set: MlDsaParameterSet::MlDsa44,
                input: if prehash {
                    HashMlDsaInput::Sha512Digest(&[0xA5; 64])
                } else {
                    HashMlDsaInput::Message(b"abc")
                },
                context: b"",
                hedging: MlDsaHedging::Required,
            };
            let policy = MlDsaSigningPolicy::default();
            let before = client
                .pool()
                .try_acquire(Authentication::None)
                .unwrap()
                .generation();
            for _ in 0..2 {
                if verify {
                    assert!(matches!(
                        client.verify_hash_ml_dsa(
                            &public(),
                            &request,
                            &[0; 2420],
                            Authentication::None
                        ),
                        Err(Error::SignatureMismatch)
                    ));
                    client
                        .verify_hash_ml_dsa(
                            &public(),
                            &request,
                            &[0xAB; 2420],
                            Authentication::None,
                        )
                        .unwrap();
                } else {
                    assert!(
                        client
                            .sign_hash_ml_dsa(
                                &private(),
                                &request,
                                &MlDsaSigningPolicy {
                                    parameter_sets: vec![]
                                },
                                Authentication::None,
                                None
                            )
                            .is_err()
                    );
                    assert!(
                        client
                            .hash_ml_dsa_capabilities(
                                &private(),
                                request.input.mode(),
                                Authentication::None
                            )
                            .unwrap()
                            .can_sign
                    );
                    assert_eq!(
                        client
                            .sign_hash_ml_dsa(
                                &private(),
                                &request,
                                &policy,
                                Authentication::None,
                                None
                            )
                            .unwrap(),
                        vec![0xAB; 2420]
                    );
                }
            }
            assert_eq!(
                client
                    .pool()
                    .try_acquire(Authentication::None)
                    .unwrap()
                    .generation(),
                before
            );
            client.close().unwrap();
            provider.finalize().unwrap();
        }
    }
}
#[test]
fn native_hash_ml_dsa_failures_discard_pooled_sessions() {
    for (verify, fault) in [(false, 13), (false, 15), (true, 18), (true, 22)] {
        let fixture = HashMlDsaModule::new(3, 2, fault, 0, 1, 0, 0, true, verify);
        let provider = Provider::load(fixture.path()).unwrap();
        let client = provider
            .client(
                &"pkcs11:token=cmac".parse().unwrap(),
                NonZeroUsize::new(1).unwrap(),
                SigningPolicy::default(),
            )
            .unwrap();
        let request = HashMlDsaRequest {
            parameter_set: MlDsaParameterSet::MlDsa44,
            input: HashMlDsaInput::Sha512Digest(&[0xA5; 64]),
            context: b"",
            hedging: MlDsaHedging::Required,
        };
        let before = client
            .pool()
            .try_acquire(Authentication::None)
            .unwrap()
            .generation();
        if verify {
            assert!(
                client
                    .verify_hash_ml_dsa(&public(), &request, &[0xAB; 2420], Authentication::None)
                    .is_err()
            );
        } else {
            assert!(
                client
                    .sign_hash_ml_dsa(
                        &private(),
                        &request,
                        &MlDsaSigningPolicy::default(),
                        Authentication::None,
                        None
                    )
                    .is_err()
            );
        }
        assert_ne!(
            client
                .pool()
                .try_acquire(Authentication::None)
                .unwrap()
                .generation(),
            before
        );
        client.close().unwrap();
        provider.finalize().unwrap();
    }
}
