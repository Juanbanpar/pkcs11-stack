// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{
    MlDsaCapabilities, MlDsaHedging, MlDsaParameterSet, MlDsaPublicKey, MlDsaRequest,
    MlDsaSigningPolicy,
};
use crate::Error;
use cryptoki::object::ParameterSetType;

#[test]
fn context_bounds_and_debug_redaction() {
    let request = MlDsaRequest {
        parameter_set: MlDsaParameterSet::MlDsa44,
        message: b"message-redaction-canary",
        context: b"context-redaction-canary",
        hedging: MlDsaHedging::Required,
    };
    assert!(!format!("{request:?}").contains("canary"));
    for length in [0, 255] {
        let context = vec![0; length];
        let bounded = MlDsaRequest {
            context: &context,
            message: b"",
            ..request
        };
        assert!(bounded.validate().is_ok());
    }
    let request = MlDsaRequest {
        context: &[0; 256],
        ..request
    };
    assert!(matches!(
        request.validate(),
        Err(Error::InvalidParameters(_))
    ));
}

#[test]
fn policies_and_capabilities_reject_disallowed_or_replaced_keys() {
    let request = MlDsaRequest {
        parameter_set: MlDsaParameterSet::MlDsa65,
        message: b"message",
        context: b"",
        hedging: MlDsaHedging::Preferred,
    };
    let mut caps = MlDsaCapabilities {
        parameter_set: MlDsaParameterSet::MlDsa65,
        can_sign: true,
        always_authenticate: true,
    };
    let policy = MlDsaSigningPolicy::default();
    caps.validate(&request, &policy).unwrap();
    assert!(matches!(
        caps.validate(
            &request,
            &MlDsaSigningPolicy {
                parameter_sets: vec![]
            }
        ),
        Err(Error::UnsupportedSigning(_))
    ));
    caps.parameter_set = MlDsaParameterSet::MlDsa44;
    assert!(matches!(
        caps.validate(&request, &policy),
        Err(Error::UnsupportedSigning(_))
    ));
    caps.parameter_set = MlDsaParameterSet::MlDsa65;
    caps.can_sign = false;
    assert!(matches!(
        caps.validate(&request, &policy),
        Err(Error::UnsupportedSigning(_))
    ));
}

#[test]
fn public_key_lengths_and_unknown_parameters_fail_closed() {
    for parameter in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ] {
        assert!(
            MlDsaPublicKey::from_bytes(parameter, vec![0; parameter.public_key_length()]).is_ok()
        );
        for length in [
            0,
            parameter.public_key_length() - 1,
            parameter.public_key_length() + 1,
        ] {
            assert!(matches!(
                MlDsaPublicKey::from_bytes(parameter, vec![0; length]),
                Err(Error::InvalidKeyOutput)
            ));
        }
    }
    let unknown = ParameterSetType::try_from(cryptoki::types::Ulong::new(0xFFFF)).unwrap();
    assert!(matches!(
        MlDsaParameterSet::from_attribute(unknown),
        Err(Error::UnsupportedSigning(_))
    ));
}
