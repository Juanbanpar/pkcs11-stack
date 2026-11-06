// SPDX-License-Identifier: MIT OR Apache-2.0
//! Client policy preflight, completed mismatch mapping and session pool reuse.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/slh_dsa_module.rs"]
mod fixture;
use fixture::SlhDsaModule;
use pkcs11_client::*;
use std::num::NonZeroUsize;
fn private() -> PrivateKeyRef {
    PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap()
}
fn public() -> PublicKeyRef {
    PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap()
}
#[test]
fn hash_slh_dsa_client_single_part_signing_and_completed_mismatch_reuse() {
    for prehash in [false, true] {
        for verify in [false, true] {
            let fixture = SlhDsaModule::hash((3, 2), 0, 0, false, (1, 0), (3, prehash));
            let provider = Provider::load(fixture.path()).unwrap();
            let client = provider
                .client(
                    &"pkcs11:token=cmac".parse().unwrap(),
                    NonZeroUsize::new(1).unwrap(),
                    SigningPolicy::default(),
                )
                .unwrap();
            let request = HashSlhDsaRequest {
                parameter_set: SlhDsaParameterSet::Sha2_128S,
                input: if prehash {
                    HashSlhDsaInput::Digest {
                        hash: DigestAlgorithm::Sha512,
                        bytes: &[0xc7; 64],
                    }
                } else {
                    HashSlhDsaInput::Message {
                        hash: DigestAlgorithm::Sha512,
                        message: b"abc",
                    }
                },
                context: b"",
                hedging: SlhDsaHedging::Required,
            };
            let policy = HashSlhDsaSigningPolicy::default();
            let before = client
                .pool()
                .try_acquire(Authentication::None)
                .unwrap()
                .generation();
            for _ in 0..2 {
                if verify {
                    assert!(matches!(
                        client.verify_hash_slh_dsa(
                            &public(),
                            &request,
                            &[0; 7856],
                            Authentication::None
                        ),
                        Err(Error::SignatureMismatch)
                    ));
                    client
                        .verify_hash_slh_dsa(
                            &public(),
                            &request,
                            &[0xAB; 7856],
                            Authentication::None,
                        )
                        .unwrap();
                } else {
                    let lease = client.pool().try_acquire(Authentication::None).unwrap();
                    let error = client
                        .sign_hash_slh_dsa(
                            &private(),
                            &request,
                            &HashSlhDsaSigningPolicy {
                                parameter_sets: vec![],
                                ..Default::default()
                            },
                            Authentication::None,
                            None,
                        )
                        .unwrap_err();
                    assert_eq!(error.kind(), ErrorKind::Policy);
                    drop(lease);
                    assert!(
                        client
                            .hash_slh_dsa_capabilities(
                                &private(),
                                request.input.mode(),
                                Authentication::None
                            )
                            .unwrap()
                            .can_sign
                    );
                    assert_eq!(
                        client
                            .sign_hash_slh_dsa(
                                &private(),
                                &request,
                                &policy,
                                Authentication::None,
                                None
                            )
                            .unwrap(),
                        vec![0xAB; 7856]
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
fn native_hash_slh_dsa_failures_discard_pooled_sessions() {
    for (verify, fault) in [(false, 17), (false, 21), (true, 24), (true, 25)] {
        let fixture = SlhDsaModule::hash((3, 2), 0, fault, false, (1, 0), (3, true));
        let provider = Provider::load(fixture.path()).unwrap();
        let client = provider
            .client(
                &"pkcs11:token=cmac".parse().unwrap(),
                NonZeroUsize::new(1).unwrap(),
                SigningPolicy::default(),
            )
            .unwrap();
        let request = HashSlhDsaRequest {
            parameter_set: SlhDsaParameterSet::Sha2_128S,
            input: HashSlhDsaInput::Digest {
                hash: DigestAlgorithm::Sha512,
                bytes: &[0xc7; 64],
            },
            context: b"",
            hedging: SlhDsaHedging::Required,
        };
        let before = client
            .pool()
            .try_acquire(Authentication::None)
            .unwrap()
            .generation();
        if verify {
            assert!(
                client
                    .verify_hash_slh_dsa(&public(), &request, &[0xAB; 7856], Authentication::None)
                    .is_err()
            );
        } else {
            assert!(
                client
                    .sign_hash_slh_dsa(
                        &private(),
                        &request,
                        &HashSlhDsaSigningPolicy::default(),
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
