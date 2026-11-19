// SPDX-License-Identifier: MIT OR Apache-2.0
use cryptoki::mechanism::{
    Mechanism,
    dsa::{HedgeType, SignAdditionalContext},
};

use crate::Error;

use super::MlDsaParameterSet;

/// Token randomness requirement for ML-DSA signing. Verification ignores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsaHedging {
    /// Require fresh randomness; the provider must fail if it cannot supply it.
    Required,
    /// Permit the provider's hedged or deterministic implementation.
    Preferred,
    /// Explicitly require deterministic signing.
    Deterministic,
}
impl MlDsaHedging {
    pub(super) fn mechanism(self) -> HedgeType {
        match self {
            Self::Required => HedgeType::Required,
            Self::Preferred => HedgeType::Preferred,
            Self::Deterministic => HedgeType::DeterministicRequired,
        }
    }
}

/// Pure ML-DSA message request, with no prehash or external-mu mode.
/// Debug omits message and context bytes. The expected parameter set guards against
/// selecting a key with different parameters under the same locator.
#[derive(Clone, Copy)]
pub struct MlDsaRequest<'a> {
    /// Expected key parameter set.
    pub parameter_set: MlDsaParameterSet,
    /// Original message, processed by CKM_ML_DSA without external hashing.
    pub message: &'a [u8],
    /// Domain-separation context, at most 255 bytes; empty means no context.
    pub context: &'a [u8],
    /// Explicit signing randomness requirement; ignored for verification.
    pub hedging: MlDsaHedging,
}
impl std::fmt::Debug for MlDsaRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaRequest")
            .field("parameter_set", &self.parameter_set)
            .field("hedging", &self.hedging)
            .finish_non_exhaustive()
    }
}
impl MlDsaRequest<'_> {
    /// Validate context length before provider access. Empty messages are valid.
    pub fn validate(&self) -> Result<(), Error> {
        if self.context.len() > 255 {
            return Err(Error::InvalidParameters("ML-DSA context exceeds 255 bytes"));
        }
        Ok(())
    }
    pub(super) fn mechanism(&self) -> Mechanism<'_> {
        Mechanism::MlDsa(SignAdditionalContext::new(
            self.hedging.mechanism(),
            if self.context.is_empty() {
                None
            } else {
                Some(self.context)
            },
        ))
    }
}

/// ML-DSA signing restrictions, independent of the classical digest-based policy.
#[derive(Clone, Debug)]
pub struct MlDsaSigningPolicy {
    /// Allowed parameter sets. An empty list disables ML-DSA signing.
    pub parameter_sets: Vec<MlDsaParameterSet>,
}
impl Default for MlDsaSigningPolicy {
    fn default() -> Self {
        Self {
            parameter_sets: vec![
                MlDsaParameterSet::MlDsa44,
                MlDsaParameterSet::MlDsa65,
                MlDsaParameterSet::MlDsa87,
            ],
        }
    }
}
impl MlDsaSigningPolicy {
    /// Check request context and allowed parameters without authentication or provider calls.
    pub fn validate(&self, request: &MlDsaRequest<'_>) -> Result<(), Error> {
        request.validate()?;
        if !self.parameter_sets.contains(&request.parameter_set) {
            return Err(Error::UnsupportedSigning("ML-DSA parameter set policy"));
        }
        Ok(())
    }
}

/// Advisory snapshot, rediscovered before each signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlDsaCapabilities {
    /// Parameter set read from the private key.
    pub parameter_set: MlDsaParameterSet,
    /// Key permission, allowed mechanisms and token flags/bounds all allow signing.
    pub can_sign: bool,
    /// A separate context-specific PIN is required after signing initialization.
    pub always_authenticate: bool,
}
impl MlDsaCapabilities {
    /// Check this snapshot against the request and application policy without signing.
    pub fn validate(
        &self,
        request: &MlDsaRequest<'_>,
        policy: &MlDsaSigningPolicy,
    ) -> Result<(), Error> {
        policy.validate(request)?;
        if self.parameter_set != request.parameter_set {
            return Err(Error::UnsupportedSigning("ML-DSA parameter set or policy"));
        }
        if !self.can_sign {
            return Err(Error::UnsupportedSigning("ML-DSA key or token permissions"));
        }
        Ok(())
    }
}

/// Length-checked public ML-DSA material; contains no private value or seed.
#[derive(Clone, Debug)]
pub struct MlDsaPublicKey {
    parameter_set: MlDsaParameterSet,
    value: Vec<u8>,
}
impl MlDsaPublicKey {
    /// Validate FIPS 204's public-key encoding length. This does not prove key ownership.
    pub fn from_bytes(parameter_set: MlDsaParameterSet, value: Vec<u8>) -> Result<Self, Error> {
        if value.len() != parameter_set.public_key_length() {
            return Err(Error::InvalidKeyOutput);
        }
        Ok(Self {
            parameter_set,
            value,
        })
    }
    /// Public-key parameter set.
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }
    /// Raw FIPS 204 public-key encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}
