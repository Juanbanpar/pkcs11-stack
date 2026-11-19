// SPDX-License-Identifier: MIT OR Apache-2.0
use cryptoki::mechanism::{
    Mechanism,
    dsa::{HedgeType, SignAdditionalContext},
};

use crate::Error;

use super::SlhDsaParameterSet;

/// Original-message allocation limit for this profile (64 MiB).
pub const SLH_DSA_MAXIMUM_MESSAGE: usize = 64 * 1024 * 1024;
/// Persistent signing/verification-only pair. No seed/private value is imported.
#[derive(Clone, Copy)]
pub struct SlhDsaKeyPairRequest<'a> {
    /// Explicit standardized parameter set.
    pub parameter_set: SlhDsaParameterSet,
    /// Nonempty shared CKA_ID, at most 128 bytes. Existing pair IDs are rejected.
    pub id: &'a [u8],
    /// Nonempty shared label, at most 128 bytes.
    pub label: &'a [u8],
    /// Require context-specific authentication after each signing initialization.
    pub always_authenticate: bool,
}
impl std::fmt::Debug for SlhDsaKeyPairRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlhDsaKeyPairRequest")
            .field("parameter_set", &self.parameter_set)
            .field("always_authenticate", &self.always_authenticate)
            .finish_non_exhaustive()
    }
}
impl SlhDsaKeyPairRequest<'_> {
    /// Check identity lengths before native access. Uniqueness is not atomic
    /// against concurrent writers; provider failures may leave partial objects.
    pub fn validate(&self) -> Result<(), Error> {
        crate::key_management::validate_secret_identity(self.id, self.label)
    }
}
/// Token randomness requirement for SLH-DSA signing. Verification ignores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlhDsaHedging {
    /// Require fresh randomness; the provider must fail if it cannot supply it.
    Required,
    /// Permit the provider's hedged or deterministic implementation.
    Preferred,
    /// Explicitly require deterministic signing.
    Deterministic,
}
impl SlhDsaHedging {
    pub(super) fn mechanism(self) -> HedgeType {
        match self {
            Self::Required => HedgeType::Required,
            Self::Preferred => HedgeType::Preferred,
            Self::Deterministic => HedgeType::DeterministicRequired,
        }
    }
}

/// Pure SLH-DSA original-message request, with no prehash mode.
/// Debug omits message and context bytes. The expected parameter set guards against
/// selecting a key with different parameters under the same locator.
#[derive(Clone, Copy)]
pub struct SlhDsaRequest<'a> {
    /// Expected key parameter set.
    pub parameter_set: SlhDsaParameterSet,
    /// Original message, processed by CKM_SLH_DSA without external hashing.
    pub message: &'a [u8],
    /// Domain-separation context, at most 255 bytes; empty means no context.
    pub context: &'a [u8],
    /// Explicit signing randomness requirement; ignored for verification.
    pub hedging: SlhDsaHedging,
}
impl std::fmt::Debug for SlhDsaRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlhDsaRequest")
            .field("parameter_set", &self.parameter_set)
            .field("hedging", &self.hedging)
            .finish_non_exhaustive()
    }
}
impl SlhDsaRequest<'_> {
    /// Validate message/context bounds before provider access. Empty messages are valid.
    pub fn validate(&self) -> Result<(), Error> {
        if self.message.len() > SLH_DSA_MAXIMUM_MESSAGE {
            return Err(Error::InvalidParameters("SLH-DSA message exceeds 64 MiB"));
        }
        if self.context.len() > 255 {
            return Err(Error::InvalidParameters(
                "SLH-DSA context exceeds 255 bytes",
            ));
        }
        Ok(())
    }
    pub(super) fn mechanism(&self) -> Mechanism<'_> {
        Mechanism::SlhDsa(SignAdditionalContext::new(
            self.hedging.mechanism(),
            if self.context.is_empty() {
                None
            } else {
                Some(self.context)
            },
        ))
    }
}

/// Pure SLH-DSA restrictions, independent of classical and ML-DSA signing policies.
#[derive(Clone, Debug)]
pub struct SlhDsaSigningPolicy {
    /// Allowed parameter sets. An empty list disables SLH-DSA signing.
    pub parameter_sets: Vec<SlhDsaParameterSet>,
}
impl Default for SlhDsaSigningPolicy {
    fn default() -> Self {
        Self {
            parameter_sets: SlhDsaParameterSet::ALL.to_vec(),
        }
    }
}
impl SlhDsaSigningPolicy {
    /// Check request context and allowed parameters without authentication or provider calls.
    pub fn validate(&self, request: &SlhDsaRequest<'_>) -> Result<(), Error> {
        request.validate()?;
        if !self.parameter_sets.contains(&request.parameter_set) {
            return Err(Error::UnsupportedSigning("SLH-DSA parameter set policy"));
        }
        Ok(())
    }
}

/// Advisory snapshot, rediscovered before each signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlhDsaCapabilities {
    /// Parameter set read from the private key.
    pub parameter_set: SlhDsaParameterSet,
    /// Key permission, allowed mechanisms and token flags/bounds all allow signing.
    pub can_sign: bool,
    /// A separate context-specific PIN is required after signing initialization.
    pub always_authenticate: bool,
}
impl SlhDsaCapabilities {
    /// Check this snapshot against the request and application policy without signing.
    pub fn validate(
        &self,
        request: &SlhDsaRequest<'_>,
        policy: &SlhDsaSigningPolicy,
    ) -> Result<(), Error> {
        policy.validate(request)?;
        if self.parameter_set != request.parameter_set {
            return Err(Error::UnsupportedSigning("SLH-DSA parameter set or policy"));
        }
        if !self.can_sign {
            return Err(Error::UnsupportedSigning(
                "SLH-DSA key or token permissions",
            ));
        }
        Ok(())
    }
}

/// Length-checked public SLH-DSA material; contains no private value or seed.
#[derive(Clone, Debug)]
pub struct SlhDsaPublicKey {
    parameter_set: SlhDsaParameterSet,
    value: Vec<u8>,
}
impl SlhDsaPublicKey {
    /// Validate FIPS 205's public-key encoding length. This does not prove key ownership.
    pub fn from_bytes(parameter_set: SlhDsaParameterSet, value: Vec<u8>) -> Result<Self, Error> {
        if value.len() != parameter_set.public_key_length() {
            return Err(Error::InvalidKeyOutput);
        }
        Ok(Self {
            parameter_set,
            value,
        })
    }
    /// Public-key parameter set.
    pub fn parameter_set(&self) -> SlhDsaParameterSet {
        self.parameter_set
    }
    /// Raw FIPS 205 public-key encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}
