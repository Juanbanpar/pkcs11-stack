// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixed-output HashML-DSA native identifiers, parameter layouts and hash separation.
#![cfg(unix)]
#[path = "fixtures/hash_ml_dsa_module.rs"]
mod fixture;
use fixture::HashMlDsaModule;
use pkcs11_runtime::*;
use secrecy::SecretString;
const HASHES: [(DigestAlgorithm, &str, usize); 8] = [
    (DigestAlgorithm::Sha224, "CKM_SHA224", 28),
    (DigestAlgorithm::Sha256, "CKM_SHA256", 32),
    (DigestAlgorithm::Sha384, "CKM_SHA384", 48),
    (DigestAlgorithm::Sha512, "CKM_SHA512", 64),
    (DigestAlgorithm::Sha3_224, "CKM_SHA3_224", 28),
    (DigestAlgorithm::Sha3_256, "CKM_SHA3_256", 32),
    (DigestAlgorithm::Sha3_384, "CKM_SHA3_384", 48),
    (DigestAlgorithm::Sha3_512, "CKM_SHA3_512", 64),
];
fn private() -> PrivateKeyRef {
    PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap()
}
fn public() -> PublicKeyRef {
    PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap()
}
fn parameters() -> HashMlDsaParameters<'static> {
    HashMlDsaParameters {
        parameter_set: MlDsaParameterSet::MlDsa44,
        context: &[0xA5; 255],
        hedging: MlDsaHedging::Required,
    }
}
#[test]
fn selected_tables_all_hashes_message_digest_and_stream_contracts() {
    for (major, minor) in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        for (hash, native, length) in HASHES {
            for (prehash, stream) in [(false, false), (true, false), (false, true)] {
                for verify in [false, true] {
                    let fixture = HashMlDsaModule::profile(
                        major, minor, 0, 0, native, length, prehash, stream, verify,
                    );
                    let module = Module::load(fixture.path()).unwrap();
                    let token = module
                        .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                        .unwrap();
                    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                    let pin = SecretString::from("1234");
                    let p = parameters().with_hash(hash);
                    let digest = vec![0xA5; length];
                    let request = HashMlDsaRequest {
                        input: if prehash {
                            HashMlDsaInput::Digest {
                                hash,
                                bytes: &digest,
                            }
                        } else {
                            HashMlDsaInput::MessageWithHash {
                                hash,
                                message: b"abc",
                            }
                        },
                        ..p.request(&[])
                    };
                    if verify {
                        let caps = session
                            .hash_ml_dsa_verification_capabilities_with_hash(&public(), hash)
                            .unwrap();
                        assert_eq!(caps.can_verify, !prehash);
                        assert_eq!(caps.can_stream, stream);
                        if stream {
                            let mut operation = session
                                .start_hash_ml_dsa_verification(&public(), p)
                                .unwrap();
                            operation.update(b"a").unwrap();
                            operation.update(b"bc").unwrap();
                            operation.finish(&[0xAB; 2420]).unwrap();
                        } else {
                            session
                                .verify_hash_ml_dsa(&public(), &request, &[0xAB; 2420])
                                .unwrap();
                        }
                    } else {
                        let caps = if stream {
                            session.hash_ml_dsa_streaming_capabilities_with_hash(&private(), hash)
                        } else {
                            session.hash_ml_dsa_capabilities(&private(), request.input.mode())
                        }
                        .unwrap();
                        caps.validate(&request, &MlDsaSigningPolicy::default())
                            .unwrap();
                        let signature = if stream {
                            let mut operation = session
                                .start_hash_ml_dsa_signing(
                                    &private(),
                                    p,
                                    &MlDsaSigningPolicy::default(),
                                    Some(Pin::Value(&pin)),
                                )
                                .unwrap();
                            operation.update(b"a").unwrap();
                            operation.update(b"bc").unwrap();
                            operation.finish().unwrap()
                        } else {
                            session
                                .sign_hash_ml_dsa(
                                    &private(),
                                    &request,
                                    &MlDsaSigningPolicy::default(),
                                    Some(Pin::Value(&pin)),
                                )
                                .unwrap()
                        };
                        assert_eq!(signature, vec![0xAB; 2420]);
                    }
                    session.info().unwrap();
                    session.close().unwrap();
                    drop(token);
                    module.finalize().unwrap();
                }
            }
        }
    }
}
#[test]
fn lengths_contexts_and_equal_length_hashes_are_distinct_before_native_init() {
    for (hash, _, length) in HASHES {
        let p = parameters().with_hash(hash);
        for n in [0, length - 1, length, length + 1, 128] {
            let bytes = vec![0; n];
            let request = HashMlDsaRequest {
                input: HashMlDsaInput::Digest {
                    hash,
                    bytes: &bytes,
                },
                ..p.request(&[])
            };
            assert_eq!(request.validate().is_ok(), n == length);
        }
        let caps = HashMlDsaCapabilities {
            parameter_set: MlDsaParameterSet::MlDsa44,
            mode: HashMlDsaMode::message(hash),
            can_sign: true,
            always_authenticate: false,
        };
        for (other, ..) in HASHES {
            assert_eq!(
                caps.validate(
                    &parameters().with_hash(other).request(b"message"),
                    &MlDsaSigningPolicy::default()
                )
                .is_ok(),
                other == hash
            );
        }
        assert!(!format!("{:?}", p.request(b"redaction-canary")).contains("canary"));
    }
    assert_eq!(
        HashMlDsaMode::message(DigestAlgorithm::Sha512),
        HashMlDsaMode::Message
    );
    assert_eq!(
        HashMlDsaMode::prehashed(DigestAlgorithm::Sha512),
        HashMlDsaMode::Prehashed
    );
}
#[test]
fn native_failures_and_unpermitted_hashes_preserve_discard_rules() {
    for (hash, native, length) in HASHES {
        for fault in [0, 11, 12, 13, 15, 27, 29] {
            let fixture =
                HashMlDsaModule::profile(3, 2, fault, 0, native, length, false, true, false);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let other = if hash == DigestAlgorithm::Sha256 {
                DigestAlgorithm::Sha3_256
            } else {
                DigestAlgorithm::Sha256
            };
            assert!(
                !session
                    .hash_ml_dsa_streaming_capabilities_with_hash(&private(), other)
                    .unwrap()
                    .can_sign
            );
            let pin = SecretString::from("1234");
            {
                let result = session.start_hash_ml_dsa_signing(
                    &private(),
                    parameters().with_hash(hash),
                    &MlDsaSigningPolicy::default(),
                    Some(Pin::Value(&pin)),
                );
                if let Ok(mut operation) = result {
                    if fault == 0 {
                        drop(operation);
                    } else if [27, 29].contains(&fault) {
                        assert!(operation.update(b"abc").is_err());
                    } else {
                        operation.update(b"abc").unwrap();
                        assert!(operation.finish().is_err());
                    }
                } else {
                    assert!([11, 12].contains(&fault));
                }
            }
            assert!(session.info().is_err());
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
