// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Error, KeyCapabilities, KeyKind, NamedCurve, SignInput, SignRequest, SignatureAlgorithm,
};

use super::types::DigestAlgorithm;

/// Policy for unhashed messages. Precomputed digests are always caller-hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashingPolicy {
    /// Require a combined token mechanism for messages.
    TokenOnly,
    /// Prefer combined mechanisms, allowing software hashing if unavailable.
    AllowSoftware,
    /// Explicitly hash messages in software and use a raw signing mechanism.
    SoftwareOnly,
}
/// Application restrictions, intersected with actual key/token capabilities.
#[derive(Debug, Clone)]
pub struct SigningPolicy {
    /// Message hashing boundary.
    pub hashing: HashingPolicy,
    /// Minimum RSA modulus size in bits.
    pub minimum_rsa_bits: usize,
    /// Allowed signature families.
    pub algorithms: Vec<SignatureAlgorithm>,
    /// Allowed named EC curves.
    pub curves: Vec<NamedCurve>,
    /// Allowed message and MGF1 digests.
    pub digests: Vec<DigestAlgorithm>,
}
impl Default for SigningPolicy {
    fn default() -> Self {
        Self {
            hashing: HashingPolicy::TokenOnly,
            minimum_rsa_bits: 2048,
            curves: vec![NamedCurve::P256, NamedCurve::P384, NamedCurve::P521],
            algorithms: vec![
                SignatureAlgorithm::RsaPkcs1,
                SignatureAlgorithm::RsaPss,
                SignatureAlgorithm::Ecdsa,
            ],
            digests: vec![
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
            ],
        }
    }
}

impl SigningPolicy {
    pub(super) fn validate(
        &self,
        capabilities: &KeyCapabilities,
        request: &SignRequest<'_>,
    ) -> Result<(), Error> {
        if capabilities.key.bits() == 0 {
            return Err(Error::InvalidParameters("zero key size"));
        }
        if !capabilities.can_sign
            || !self.algorithms.contains(&request.algorithm)
            || !self.digests.contains(&request.digest)
        {
            return Err(Error::UnsupportedSigning("key or policy disallows signing"));
        }
        match (request.algorithm, capabilities.key) {
            (SignatureAlgorithm::Ecdsa, KeyKind::Ec(curve)) if self.curves.contains(&curve) => {}
            (SignatureAlgorithm::RsaPkcs1 | SignatureAlgorithm::RsaPss, KeyKind::Rsa { bits })
                if bits >= self.minimum_rsa_bits => {}
            _ => return Err(Error::UnsupportedSigning("key type or size")),
        }
        if let SignInput::Digest(value) = request.input {
            if value.len() != request.digest.output_len() {
                return Err(Error::InvalidParameters("digest length"));
            }
        }
        match (request.algorithm, request.pss) {
            (SignatureAlgorithm::RsaPss, Some(pss)) => {
                if !self.digests.contains(&pss.mgf_digest) {
                    return Err(Error::UnsupportedSigning("MGF digest policy"));
                }
                let encoded_len = (capabilities.key.bits() - 1).div_ceil(8);
                if pss.salt_len > encoded_len.saturating_sub(request.digest.output_len() + 2)
                    || encoded_len < request.digest.output_len() + 2
                {
                    return Err(Error::InvalidParameters("PSS salt does not fit modulus"));
                }
            }
            (SignatureAlgorithm::RsaPss, None) => {
                return Err(Error::InvalidParameters("PSS parameters required"));
            }
            (_, Some(_)) => {
                return Err(Error::InvalidParameters(
                    "PSS parameters on another algorithm",
                ));
            }
            _ => {}
        }
        if request.algorithm == SignatureAlgorithm::RsaPkcs1
            && capabilities.key.bits().div_ceil(8) < request.digest.output_len() + 19 + 11
        {
            return Err(Error::InvalidParameters("DigestInfo does not fit modulus"));
        }

        Ok(())
    }
}
