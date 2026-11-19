// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AttributeType, Error, Function, MechanismType, Object, ObjectClass, Pin, PrivateKeyRef,
    PublicKeyRef, Session,
    error::{backend, map_function_not_supported},
};
use cryptoki::{
    error::{Error as CryptokiError, RvError},
    mechanism::{
        Mechanism,
        dsa::{HashSignAdditionalContext, SignAdditionalContext},
    },
    session::UserType,
};

use super::{MlDsaHedging, MlDsaParameterSet};
use crate::signing::prehash::{HashInput, PrehashAlgorithm};

fn message_type(hash: PrehashAlgorithm) -> MechanismType {
    match hash {
        PrehashAlgorithm::Sha224 => MechanismType::HASH_ML_DSA_SHA224,
        PrehashAlgorithm::Sha256 => MechanismType::HASH_ML_DSA_SHA256,
        PrehashAlgorithm::Sha384 => MechanismType::HASH_ML_DSA_SHA384,
        PrehashAlgorithm::Sha512 => MechanismType::HASH_ML_DSA_SHA512,
        PrehashAlgorithm::Sha3_224 => MechanismType::HASH_ML_DSA_SHA3_224,
        PrehashAlgorithm::Sha3_256 => MechanismType::HASH_ML_DSA_SHA3_256,
        PrehashAlgorithm::Sha3_384 => MechanismType::HASH_ML_DSA_SHA3_384,
        PrehashAlgorithm::Sha3_512 => MechanismType::HASH_ML_DSA_SHA3_512,
        PrehashAlgorithm::Shake128 => MechanismType::HASH_ML_DSA_SHAKE128,
        PrehashAlgorithm::Shake256 => MechanismType::HASH_ML_DSA_SHAKE256,
    }
}

fn message_mechanism<'a>(
    hash: PrehashAlgorithm,
    hedging: MlDsaHedging,
    context: Option<&'a [u8]>,
) -> Mechanism<'a> {
    let parameters = SignAdditionalContext::new(hedging.mechanism(), context);
    match hash {
        PrehashAlgorithm::Sha224 => Mechanism::HashMlDsaSha224(parameters),
        PrehashAlgorithm::Sha256 => Mechanism::HashMlDsaSha256(parameters),
        PrehashAlgorithm::Sha384 => Mechanism::HashMlDsaSha384(parameters),
        PrehashAlgorithm::Sha512 => Mechanism::HashMlDsaSha512(parameters),
        PrehashAlgorithm::Sha3_224 => Mechanism::HashMlDsaSha3_224(parameters),
        PrehashAlgorithm::Sha3_256 => Mechanism::HashMlDsaSha3_256(parameters),
        PrehashAlgorithm::Sha3_384 => Mechanism::HashMlDsaSha3_384(parameters),
        PrehashAlgorithm::Sha3_512 => Mechanism::HashMlDsaSha3_512(parameters),
        PrehashAlgorithm::Shake128 => Mechanism::HashMlDsaShake128(parameters),
        PrehashAlgorithm::Shake256 => Mechanism::HashMlDsaShake256(parameters),
    }
}

/// HashML-DSA request. Debug omits message, digest and context bytes.
#[derive(Clone, Copy)]
pub struct HashMlDsaRequest<'a> {
    /// Expected key parameter set.
    pub parameter_set: MlDsaParameterSet,
    /// Original message or caller digest.
    pub input: HashInput<'a>,
    /// FIPS 204 context, at most 255 bytes.
    pub context: &'a [u8],
    /// Explicit signing randomness requirement; ignored for verification.
    pub hedging: MlDsaHedging,
}

impl std::fmt::Debug for HashMlDsaRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashMlDsaRequest")
            .field("parameter_set", &self.parameter_set)
            .field("input", &self.input)
            .field("hedging", &self.hedging)
            .finish_non_exhaustive()
    }
}

impl HashMlDsaRequest<'_> {
    /// Validate bounds and the prehash contract before provider access.
    pub fn validate(&self) -> Result<(), Error> {
        if self.context.len() > 255 {
            return Err(Error::InvalidParameters(
                "HashML-DSA context exceeds 255 bytes",
            ));
        }
        self.input.validate()?;
        if matches!(self.input, HashInput::Message { message, .. } if message.len() > 64 * 1024 * 1024)
        {
            return Err(Error::InvalidParameters(
                "HashML-DSA message exceeds 64 MiB",
            ));
        }
        Ok(())
    }

    fn mechanism(&self) -> Result<Mechanism<'_>, Error> {
        let context = (!self.context.is_empty()).then_some(self.context);
        match self.input {
            HashInput::Message { hash, .. } => Ok(message_mechanism(hash, self.hedging, context)),
            HashInput::Digest { hash, .. } => {
                let hash_mechanism = hash
                    .mechanism()
                    .ok_or(Error::UnsupportedSigning("HashML-DSA XOF prehash"))?;
                Ok(Mechanism::HashMlDsa(HashSignAdditionalContext::new(
                    self.hedging.mechanism(),
                    context,
                    hash_mechanism,
                )))
            }
        }
    }

    fn mode_mechanism(&self) -> MechanismType {
        match self.input {
            HashInput::Message { hash, .. } => message_type(hash),
            HashInput::Digest { .. } => MechanismType::HASH_ML_DSA,
        }
    }
}

/// HashML-DSA signing policy.
#[derive(Clone, Debug)]
pub struct HashMlDsaSigningPolicy {
    /// Allowed parameter sets.
    pub parameter_sets: Vec<MlDsaParameterSet>,
    /// Allowed prehash algorithms.
    pub hashes: Vec<PrehashAlgorithm>,
}
impl Default for HashMlDsaSigningPolicy {
    fn default() -> Self {
        Self {
            parameter_sets: vec![
                MlDsaParameterSet::MlDsa44,
                MlDsaParameterSet::MlDsa65,
                MlDsaParameterSet::MlDsa87,
            ],
            hashes: PrehashAlgorithm::ALL.to_vec(),
        }
    }
}
impl HashMlDsaSigningPolicy {
    /// Validate policy and request without provider access.
    pub fn validate(&self, request: &HashMlDsaRequest<'_>) -> Result<(), Error> {
        request.validate()?;
        if !self.parameter_sets.contains(&request.parameter_set)
            || !self.hashes.contains(&request.input.hash())
        {
            return Err(Error::UnsupportedSigning("HashML-DSA policy"));
        }
        Ok(())
    }
}

/// Advisory HashML-DSA signing snapshot for one hash/mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashMlDsaCapabilities {
    /// Actual key parameter set.
    pub parameter_set: MlDsaParameterSet,
    /// Prehash algorithm.
    pub hash: PrehashAlgorithm,
    /// Whether the caller supplies a digest.
    pub prehashed: bool,
    /// Key permission, allowed mechanism and token flags agree.
    pub can_sign: bool,
    /// Context authentication is required after init.
    pub always_authenticate: bool,
}

fn capabilities(
    object: &Object<'_, '_>,
    hash: PrehashAlgorithm,
    prehashed: bool,
) -> Result<HashMlDsaCapabilities, Error> {
    let parameter_set = super::parameter_set(object, ObjectClass::PRIVATE_KEY)?;
    let mode = if prehashed {
        MechanismType::HASH_ML_DSA
    } else {
        message_type(hash)
    };
    let module = object.session.token().module.raw()?;
    let can_sign = super::permission(object, AttributeType::Sign)?
        && super::allowed_mechanism(object, mode)?
        && super::mechanism_support(object.session.token(), parameter_set, mode, |info| {
            info.sign()
        })?
        && [Function::SignInit, Function::Sign]
            .into_iter()
            .all(|function| module.is_fn_supported(function));
    Ok(HashMlDsaCapabilities {
        parameter_set,
        hash,
        prehashed,
        can_sign,
        always_authenticate: super::permission(object, AttributeType::AlwaysAuthenticate)?,
    })
}

impl Session<'_> {
    /// Inspect a private key's HashML-DSA signing support for one hash/mode.
    pub fn hash_ml_dsa_capabilities(
        &mut self,
        key: &PrivateKeyRef,
        hash: PrehashAlgorithm,
        prehashed: bool,
    ) -> Result<HashMlDsaCapabilities, Error> {
        capabilities(&self.resolve(key.as_object_ref())?, hash, prehashed)
    }

    /// Sign one HashML-DSA message or digest.
    pub fn sign_hash_ml_dsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &HashMlDsaRequest<'_>,
        policy: &HashMlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        policy.validate(request)?;
        let object = self.resolve(key.as_object_ref())?;
        let caps = capabilities(&object, request.input.hash(), request.input.is_prehashed())?;
        if caps.parameter_set != request.parameter_set || !caps.can_sign {
            return Err(Error::UnsupportedSigning("HashML-DSA key or permissions"));
        }
        let pin = object
            .session
            .prepare_context_pin(caps.always_authenticate, context_pin)?;
        let mechanism = request.mechanism()?;
        let raw = object.session.begin_operation()?;
        let signature = if caps.always_authenticate {
            raw.sign_init(&mechanism, object.handle)
                .map_err(|e| backend("HashML-DSA sign init", e))?;
            crate::session::login_with_pin(raw, UserType::ContextSpecific, pin)
                .map_err(|e| backend("HashML-DSA context login", e))?;
            raw.sign_update(request.input.bytes())
                .map_err(|e| backend("HashML-DSA sign update", e))?;
            raw.sign_final()
                .map_err(|e| backend("HashML-DSA sign final", e))?
        } else {
            raw.sign(&mechanism, object.handle, request.input.bytes())
                .map_err(|e| backend("HashML-DSA sign", e))?
        };
        if signature.len() != request.parameter_set.signature_length() {
            return Err(Error::InvalidSignature);
        }
        object.session.healthy.set(true);
        Ok(signature)
    }

    /// Verify one HashML-DSA signature on the token.
    pub fn verify_hash_ml_dsa(
        &mut self,
        key: &PublicKeyRef,
        request: &HashMlDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        request.validate()?;
        if signature.len() != request.parameter_set.signature_length() {
            return Err(Error::SignatureMismatch);
        }
        let object = self.resolve(key.as_object_ref())?;
        let parameter = super::parameter_set(&object, ObjectClass::PUBLIC_KEY)?;
        let mode = request.mode_mechanism();
        if parameter != request.parameter_set
            || !super::permission(&object, AttributeType::Verify)?
            || !super::allowed_mechanism(&object, mode)?
            || !super::mechanism_support(object.session.token(), parameter, mode, |info| {
                info.verify()
            })?
        {
            return Err(Error::UnsupportedSigning(
                "HashML-DSA verification permissions",
            ));
        }
        let mechanism = request.mechanism()?;
        let raw = object.session.begin_operation()?;
        match raw.verify(&mechanism, object.handle, request.input.bytes(), signature) {
            Ok(()) => {
                object.session.healthy.set(true);
                Ok(())
            }
            Err(CryptokiError::Pkcs11(
                RvError::SignatureInvalid | RvError::SignatureLenRange,
                Function::Verify,
            )) => {
                object.session.healthy.set(true);
                Err(Error::SignatureMismatch)
            }
            Err(error) => Err(map_function_not_supported(
                backend("HashML-DSA verify", error),
                Error::UnsupportedVerification("HashML-DSA verification unavailable"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_reject_short_and_xof_prehashes() {
        let request = HashMlDsaRequest {
            parameter_set: MlDsaParameterSet::MlDsa65,
            input: HashInput::Digest {
                hash: PrehashAlgorithm::Sha256,
                bytes: &[0; 32],
            },
            context: b"context",
            hedging: MlDsaHedging::Required,
        };
        request.validate().unwrap();
        assert!(
            HashMlDsaRequest {
                input: HashInput::Digest {
                    hash: PrehashAlgorithm::Sha256,
                    bytes: &[0; 31],
                },
                ..request
            }
            .validate()
            .is_err()
        );
        for hash in [PrehashAlgorithm::Sha3_256, PrehashAlgorithm::Shake128] {
            assert!(
                HashMlDsaRequest {
                    input: HashInput::Digest {
                        hash,
                        bytes: &[0; 32],
                    },
                    ..request
                }
                .validate()
                .is_err()
            );
        }
        assert!(!format!("{request:?}").contains("context"));
    }
}
