// SPDX-License-Identifier: MIT OR Apache-2.0
//! FIPS 205 profile bounds and public encoding contracts.
use pkcs11_runtime::*;
#[test]
fn fips205_lengths_identity_bounds_context_and_debug_redaction() {
    let public = [32, 32, 48, 48, 64, 64, 32, 32, 48, 48, 64, 64];
    let signature = [
        7856, 17088, 16224, 35664, 29792, 49856, 7856, 17088, 16224, 35664, 29792, 49856,
    ];
    for (index, parameter_set) in SlhDsaParameterSet::ALL.into_iter().enumerate() {
        assert_eq!(parameter_set.public_key_length(), public[index]);
        assert_eq!(parameter_set.signature_length(), signature[index]);
        SlhDsaPublicKey::from_bytes(parameter_set, vec![0; public[index]]).unwrap();
        assert!(SlhDsaPublicKey::from_bytes(parameter_set, vec![0; public[index] + 1]).is_err());
        let request = SlhDsaRequest {
            parameter_set,
            message: b"message-canary",
            context: b"context-canary",
            hedging: SlhDsaHedging::Required,
        };
        assert!(!format!("{request:?}").contains("canary"));
        for len in [0, 255] {
            SlhDsaRequest {
                context: &vec![0; len],
                ..request
            }
            .validate()
            .unwrap();
        }
        assert!(
            SlhDsaRequest {
                context: &[0; 256],
                ..request
            }
            .validate()
            .is_err()
        );
        assert!(
            SlhDsaSigningPolicy {
                parameter_sets: vec![]
            }
            .validate(&request)
            .is_err()
        );
        SlhDsaSigningPolicy::default().validate(&request).unwrap();
        let key = SlhDsaKeyPairRequest {
            parameter_set,
            id: b"id",
            label: b"label",
            always_authenticate: false,
        };
        for len in [0, 129] {
            assert!(
                SlhDsaKeyPairRequest {
                    id: &vec![0; len],
                    ..key
                }
                .validate()
                .is_err()
            );
            assert!(
                SlhDsaKeyPairRequest {
                    label: &vec![0; len],
                    ..key
                }
                .validate()
                .is_err()
            );
        }
        SlhDsaKeyPairRequest {
            id: &[0; 128],
            label: &[0; 128],
            ..key
        }
        .validate()
        .unwrap();
    }
    let large = vec![0; SLH_DSA_MAXIMUM_MESSAGE + 1];
    let request = SlhDsaRequest {
        parameter_set: SlhDsaParameterSet::Sha2_128S,
        message: &large,
        context: &[],
        hedging: SlhDsaHedging::Required,
    };
    assert!(request.validate().is_err());
    SlhDsaRequest {
        message: &large[..SLH_DSA_MAXIMUM_MESSAGE],
        ..request
    }
    .validate()
    .unwrap();
}
