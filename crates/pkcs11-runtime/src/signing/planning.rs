// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, KeyCapabilities, MechanismType, SignInput, SignRequest};
use cryptoki::mechanism::Mechanism;

use super::types::SignatureAlgorithm;
use super::{HashingPolicy, SigningPolicy, ecdsa, rsa};

/// Where the input message is hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashLocation {
    /// Token combined hash/sign mechanism.
    Token,
    /// Runtime software hashing explicitly permitted by policy.
    Software,
    /// Digest supplied by caller.
    Caller,
}
/// A planning result, never an authorization or a cached operational handle.
#[derive(Debug, Clone)]
pub struct SignPlan {
    mechanism: MechanismType,
    hashing: HashLocation,
    multipart: bool,
}
impl SignPlan {
    /// Selected PKCS#11 mechanism.
    pub fn mechanism(&self) -> MechanismType {
        self.mechanism
    }
    /// Selected hashing boundary.
    pub fn hash_location(&self) -> HashLocation {
        self.hashing
    }
    /// Whether context login must occur between init and multipart signing.
    pub fn context_authentication(&self) -> bool {
        self.multipart
    }
}
impl KeyCapabilities {
    /// Pure planning, usable without loading a module. Unknown facts fail closed.
    pub fn plan(
        &self,
        request: &SignRequest<'_>,
        policy: &SigningPolicy,
    ) -> Result<SignPlan, Error> {
        policy.validate(self, request)?;
        let combined = mechanism(request, true).ok().map(|m| m.mechanism_type());
        let raw = mechanism(request, false)?.mechanism_type();
        let supports = |m| {
            self.mechanisms.iter().any(|v| {
                v.mechanism == m
                    && v.can_sign
                    && self.key.bits() >= v.minimum_bits
                    && self.key.bits() <= v.maximum_bits
            }) && self
                .allowed_mechanisms
                .as_ref()
                .is_none_or(|allowed| allowed.is_empty() || allowed.contains(&m))
        };
        let (selected, hashing) = match request.input {
            SignInput::Digest(_) if supports(raw) => (raw, HashLocation::Caller),
            SignInput::Message(_)
                if policy.hashing != HashingPolicy::SoftwareOnly
                    && combined.is_some_and(supports) =>
            {
                (combined.expect("checked above"), HashLocation::Token)
            }
            SignInput::Message(_)
                if policy.hashing != HashingPolicy::TokenOnly && supports(raw) =>
            {
                (raw, HashLocation::Software)
            }
            _ => return Err(Error::UnsupportedSigning("no permitted mechanism")),
        };
        if self.always_authenticate && hashing != HashLocation::Token {
            return Err(Error::UnsupportedSigning(
                "context authentication needs a combined hash/sign mechanism with cryptoki 0.12",
            ));
        }
        Ok(SignPlan {
            mechanism: selected,
            hashing,
            multipart: self.always_authenticate,
        })
    }
}

pub(super) fn mechanism(
    request: &SignRequest<'_>,
    combined: bool,
) -> Result<Mechanism<'static>, Error> {
    match request.algorithm {
        SignatureAlgorithm::RsaPkcs1 => Ok(rsa::pkcs1_mechanism(request.digest, combined)),
        SignatureAlgorithm::RsaPss => rsa::pss_mechanism(request, combined),
        SignatureAlgorithm::Ecdsa => Ok(ecdsa::mechanism(request.digest, combined)),
    }
}
