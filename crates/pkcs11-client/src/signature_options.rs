// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::*;

/// Owned parameters for a typed signing or verification request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureParameters {
    /// Signature family.
    pub algorithm: SignatureAlgorithm,
    /// SHA-2 message digest.
    pub digest: DigestAlgorithm,
    /// Explicit PSS parameters; absent for other families.
    pub pss: Option<PssParameters>,
}
impl SignatureParameters {
    /// Borrow input without retaining its bytes.
    pub fn request(self, input: SignInput<'_>) -> SignRequest<'_> {
        SignRequest {
            algorithm: self.algorithm,
            digest: self.digest,
            pss: self.pss,
            input,
        }
    }
}

/// One advisory message-signing choice under a client's policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningChoice {
    /// Parameters to submit; execution rediscovers capabilities.
    pub parameters: SignatureParameters,
    /// Planned mechanism, for display only.
    pub mechanism: MechanismType,
    /// Planned hashing boundary.
    pub hashing: HashLocation,
}

/// Current choices and per-operation authentication requirement.
#[derive(Clone, Debug)]
pub struct SigningOptions {
    /// Whether this key requires a context PIN or protected authentication path.
    pub always_authenticate: bool,
    /// SHA-2 choices; PSS uses matching MGF1 digest and digest-length salt.
    pub choices: Vec<SigningChoice>,
}
pub(crate) fn candidates(key: KeyKind) -> Vec<SignatureParameters> {
    let algorithms: &[SignatureAlgorithm] = match key {
        KeyKind::Rsa { .. } => &[SignatureAlgorithm::RsaPkcs1, SignatureAlgorithm::RsaPss],
        KeyKind::Ec(_) => &[SignatureAlgorithm::Ecdsa],
    };
    algorithms
        .iter()
        .flat_map(|&algorithm| {
            [
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
            ]
            .into_iter()
            .map(move |digest| SignatureParameters {
                algorithm,
                digest,
                pss: (algorithm == SignatureAlgorithm::RsaPss).then_some(PssParameters {
                    mgf_digest: digest,
                    salt_len: digest.output_len(),
                }),
            })
        })
        .collect()
}
pub(crate) fn options(caps: &KeyCapabilities, policy: &SigningPolicy) -> SigningOptions {
    SigningOptions {
        always_authenticate: caps.always_authenticate,
        choices: candidates(caps.key)
            .into_iter()
            .filter_map(|parameters| {
                caps.plan(&parameters.request(SignInput::Message(&[])), policy)
                    .ok()
                    .map(|plan| SigningChoice {
                        parameters,
                        mechanism: plan.mechanism(),
                        hashing: plan.hash_location(),
                    })
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn choices_obey_key_mechanisms_policy_and_context_authentication() {
        let mut caps = KeyCapabilities {
            key: KeyKind::Rsa { bits: 2048 },
            can_sign: true,
            always_authenticate: false,
            allowed_mechanisms: None,
            mechanisms: vec![SigningMechanism {
                mechanism: MechanismType::SHA384_RSA_PKCS,
                can_sign: true,
                minimum_bits: 2048,
                maximum_bits: 4096,
            }],
        };
        let mut policy = SigningPolicy::default();
        let choices = options(&caps, &policy);
        assert_eq!(choices.choices.len(), 1);
        assert_eq!(
            choices.choices[0].parameters.digest,
            DigestAlgorithm::Sha384
        );
        caps.allowed_mechanisms = Some(vec![MechanismType::RSA_PKCS]);
        assert!(options(&caps, &policy).choices.is_empty());
        caps.allowed_mechanisms = None;
        caps.mechanisms[0].mechanism = MechanismType::RSA_PKCS;
        assert!(options(&caps, &policy).choices.is_empty());
        policy.hashing = HashingPolicy::AllowSoftware;
        assert_eq!(options(&caps, &policy).choices.len(), 3);
        caps.always_authenticate = true;
        assert!(options(&caps, &policy).choices.is_empty());
        caps.mechanisms[0].mechanism = MechanismType::SHA384_RSA_PKCS;
        assert!(options(&caps, &policy).always_authenticate);
        caps.can_sign = false;
        assert!(options(&caps, &policy).choices.is_empty());
    }
}
