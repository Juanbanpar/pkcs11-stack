// SPDX-License-Identifier: MIT OR Apache-2.0
//! HashSLH-DSA has explicit input and prehash policy, separate from pure signing.
use pkcs11_runtime::*;
#[test]
fn input_lengths_contexts_policy_and_redaction() {
    let hashes = HashSlhDsaSigningPolicy {
        allow_reduced_strength: true,
        ..Default::default()
    }
    .hashes;
    for hash in hashes {
        let digest = vec![0x63; hash.output_len()];
        let request = HashSlhDsaRequest {
            parameter_set: SlhDsaParameterSet::Sha2_128F,
            input: HashSlhDsaInput::Digest {
                hash,
                bytes: &digest,
            },
            context: b"context-canary",
            hedging: SlhDsaHedging::Required,
        };
        assert_eq!(request.input.mode(), HashSlhDsaMode::Prehashed(hash));
        assert_eq!(request.input.bytes(), digest);
        assert!(!format!("{request:?}").contains("canary"));
        assert!(!format!("{request:?}").contains("99, 99"));
        HashSlhDsaSigningPolicy {
            allow_reduced_strength: true,
            ..Default::default()
        }
        .validate(&request)
        .unwrap();
        for length in [0, hash.output_len() - 1, hash.output_len() + 1] {
            assert!(
                HashSlhDsaRequest {
                    input: HashSlhDsaInput::Digest {
                        hash,
                        bytes: &vec![0; length]
                    },
                    ..request
                }
                .validate()
                .is_err()
            );
        }
        for context in [b"".as_slice(), &[0; 255]] {
            HashSlhDsaRequest { context, ..request }.validate().unwrap();
        }
        assert!(
            HashSlhDsaRequest {
                context: &[0; 256],
                ..request
            }
            .validate()
            .is_err()
        );
        for policy in [
            HashSlhDsaSigningPolicy {
                hashes: vec![],
                ..Default::default()
            },
            HashSlhDsaSigningPolicy {
                parameter_sets: vec![],
                ..Default::default()
            },
            HashSlhDsaSigningPolicy {
                hashes: vec![if hash == DigestAlgorithm::Sha256 {
                    DigestAlgorithm::Sha512
                } else {
                    DigestAlgorithm::Sha256
                }],
                ..Default::default()
            },
        ] {
            assert!(policy.validate(&request).is_err());
        }
        let caps = HashSlhDsaCapabilities {
            parameter_set: request.parameter_set,
            mode: request.input.mode(),
            can_sign: true,
            always_authenticate: false,
        };
        caps.validate(
            &request,
            &HashSlhDsaSigningPolicy {
                allow_reduced_strength: true,
                ..Default::default()
            },
        )
        .unwrap();
        let message = HashSlhDsaRequest {
            input: HashSlhDsaInput::Message {
                hash,
                message: &digest,
            },
            ..request
        };
        assert!(
            caps.validate(
                &message,
                &HashSlhDsaSigningPolicy {
                    allow_reduced_strength: true,
                    ..Default::default()
                }
            )
            .is_err()
        );
    }
    let large = vec![0; SLH_DSA_MAXIMUM_MESSAGE + 1];
    for (message, valid) in [
        (b"".as_slice(), true),
        (&large[..SLH_DSA_MAXIMUM_MESSAGE], true),
        (large.as_slice(), false),
    ] {
        let request = HashSlhDsaRequest {
            parameter_set: SlhDsaParameterSet::Shake256F,
            input: HashSlhDsaInput::Message {
                hash: DigestAlgorithm::Sha3_512,
                message,
            },
            context: &[],
            hedging: SlhDsaHedging::Preferred,
        };
        assert_eq!(request.validate().is_ok(), valid);
    }
}

#[test]
fn default_policy_preserves_each_parameter_sets_claimed_strength() {
    let policy = HashSlhDsaSigningPolicy::default();
    for parameter_set in SlhDsaParameterSet::ALL {
        for hash in policy.hashes.iter().copied() {
            let request = HashSlhDsaRequest {
                parameter_set,
                input: HashSlhDsaInput::Message { hash, message: b"" },
                context: &[],
                hedging: SlhDsaHedging::Required,
            };
            assert_eq!(
                policy.validate(&request).is_ok(),
                hash.output_len() >= parameter_set.public_key_length()
            );
            HashSlhDsaSigningPolicy {
                allow_reduced_strength: true,
                ..policy.clone()
            }
            .validate(&request)
            .unwrap();
        }
    }
}
