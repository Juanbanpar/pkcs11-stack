// SPDX-License-Identifier: MIT OR Apache-2.0
//! HashML-DSA and HashSLH-DSA prehash signatures through published upstream
//! `cryptoki` variants.
//!
//! Fixed-output SHA-2/SHA-3 prehashes support both token hashing and caller
//! digests. SHAKE prehashes are available only as token-hashed message
//! mechanisms; there is no standalone SHAKE digest mechanism to pass as a
//! prehash parameter.

use crate::{
    AttributeType, Error, Function, MechanismType, MlDsaHedging, MlDsaParameterSet, Object,
    ObjectClass, Pin, PrivateKeyRef, PublicKeyRef, Session, SlhDsaHedging, SlhDsaParameterSet,
    error::{backend, map_function_not_supported},
    ml_dsa, slh_dsa,
};
use cryptoki::{
    error::{Error as CryptokiError, RvError},
    mechanism::{
        Mechanism,
        dsa::{HashSignAdditionalContext, SignAdditionalContext},
    },
    session::UserType,
};

/// Fixed-output or SHAKE prehash algorithm for HashML-DSA/HashSLH-DSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrehashAlgorithm {
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// SHAKE128. Token-hashed message profiles only.
    Shake128,
    /// SHAKE256. Token-hashed message profiles only.
    Shake256,
}

impl PrehashAlgorithm {
    /// Fixed-output prehash algorithms usable with caller-supplied digests.
    pub const FIXED: [Self; 8] = [
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
    ];
    /// Every supported prehash.
    pub const ALL: [Self; 10] = [
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
        Self::Shake128,
        Self::Shake256,
    ];

    /// Output length in bytes. SHAKE lengths follow FIPS 204/205 prehash profiles.
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha3_256 | Self::Shake128 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 | Self::Shake256 => 64,
        }
    }

    /// Whether this is an extendable-output function.
    pub fn is_xof(self) -> bool {
        matches!(self, Self::Shake128 | Self::Shake256)
    }

    /// Hash mechanism for a caller-supplied digest, if one exists upstream.
    ///
    /// Published `cryptoki` 0.12.1 exposes standalone SHA-2 mechanisms only.
    /// SHA3 and SHAKE are available through the combined message mechanisms.
    pub fn mechanism(self) -> Option<MechanismType> {
        Some(match self {
            Self::Sha224 => MechanismType::SHA224,
            Self::Sha256 => MechanismType::SHA256,
            Self::Sha384 => MechanismType::SHA384,
            Self::Sha512 => MechanismType::SHA512,
            Self::Sha3_224
            | Self::Sha3_256
            | Self::Sha3_384
            | Self::Sha3_512
            | Self::Shake128
            | Self::Shake256 => return None,
        })
    }
}

impl std::fmt::Display for PrehashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Sha3_224 => "sha3-224",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
            Self::Shake128 => "shake128",
            Self::Shake256 => "shake256",
        })
    }
}

/// Original message or caller-provided digest. Debug omits input bytes.
#[derive(Clone, Copy)]
pub enum HashInput<'a> {
    /// Hash the original message on the token.
    Message {
        /// Prehash algorithm selected by the combined mechanism.
        hash: PrehashAlgorithm,
        /// Original message, at most 64 MiB.
        message: &'a [u8],
    },
    /// Supply an already computed fixed-output digest.
    Digest {
        /// Fixed-output prehash algorithm.
        hash: PrehashAlgorithm,
        /// Exactly `hash.output_len()` bytes.
        bytes: &'a [u8],
    },
}

impl std::fmt::Debug for HashInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashInput")
            .field("hash", &self.hash())
            .field("prehashed", &self.is_prehashed())
            .finish_non_exhaustive()
    }
}

impl<'a> HashInput<'a> {
    /// Selected prehash algorithm.
    pub fn hash(self) -> PrehashAlgorithm {
        match self {
            Self::Message { hash, .. } | Self::Digest { hash, .. } => hash,
        }
    }

    /// Whether the caller supplied a digest.
    pub fn is_prehashed(self) -> bool {
        matches!(self, Self::Digest { .. })
    }

    /// Borrow the input bytes.
    pub fn bytes(self) -> &'a [u8] {
        match self {
            Self::Message { message, .. } => message,
            Self::Digest { bytes, .. } => bytes,
        }
    }

    fn validate(self) -> Result<(), Error> {
        if let Self::Digest { hash, bytes } = self {
            if hash.mechanism().is_none() || bytes.len() != hash.output_len() {
                return Err(Error::InvalidParameters(
                    "prehash digest length or unsupported prehash",
                ));
            }
        }
        Ok(())
    }
}

fn ml_dsa_message_type(hash: PrehashAlgorithm) -> MechanismType {
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

fn slh_dsa_message_type(hash: PrehashAlgorithm) -> MechanismType {
    match hash {
        PrehashAlgorithm::Sha224 => MechanismType::HASH_SLH_DSA_SHA224,
        PrehashAlgorithm::Sha256 => MechanismType::HASH_SLH_DSA_SHA256,
        PrehashAlgorithm::Sha384 => MechanismType::HASH_SLH_DSA_SHA384,
        PrehashAlgorithm::Sha512 => MechanismType::HASH_SLH_DSA_SHA512,
        PrehashAlgorithm::Sha3_224 => MechanismType::HASH_SLH_DSA_SHA3_224,
        PrehashAlgorithm::Sha3_256 => MechanismType::HASH_SLH_DSA_SHA3_256,
        PrehashAlgorithm::Sha3_384 => MechanismType::HASH_SLH_DSA_SHA3_384,
        PrehashAlgorithm::Sha3_512 => MechanismType::HASH_SLH_DSA_SHA3_512,
        PrehashAlgorithm::Shake128 => MechanismType::HASH_SLH_DSA_SHAKE128,
        PrehashAlgorithm::Shake256 => MechanismType::HASH_SLH_DSA_SHAKE256,
    }
}

fn ml_dsa_message_mechanism<'a>(
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

fn slh_dsa_message_mechanism<'a>(
    hash: PrehashAlgorithm,
    hedging: SlhDsaHedging,
    context: Option<&'a [u8]>,
) -> Mechanism<'a> {
    let parameters = SignAdditionalContext::new(hedging.mechanism(), context);
    match hash {
        PrehashAlgorithm::Sha224 => Mechanism::HashSlhDsaSha224(parameters),
        PrehashAlgorithm::Sha256 => Mechanism::HashSlhDsaSha256(parameters),
        PrehashAlgorithm::Sha384 => Mechanism::HashSlhDsaSha384(parameters),
        PrehashAlgorithm::Sha512 => Mechanism::HashSlhDsaSha512(parameters),
        PrehashAlgorithm::Sha3_224 => Mechanism::HashSlhDsaSha3_224(parameters),
        PrehashAlgorithm::Sha3_256 => Mechanism::HashSlhDsaSha3_256(parameters),
        PrehashAlgorithm::Sha3_384 => Mechanism::HashSlhDsaSha3_384(parameters),
        PrehashAlgorithm::Sha3_512 => Mechanism::HashSlhDsaSha3_512(parameters),
        PrehashAlgorithm::Shake128 => Mechanism::HashSlhDsaShake128(parameters),
        PrehashAlgorithm::Shake256 => Mechanism::HashSlhDsaShake256(parameters),
    }
}

fn message_mechanism_type(
    hash: PrehashAlgorithm,
    ml_dsa_family: bool,
) -> Result<MechanismType, Error> {
    Ok(if ml_dsa_family {
        ml_dsa_message_type(hash)
    } else {
        slh_dsa_message_type(hash)
    })
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
            HashInput::Message { hash, .. } => {
                Ok(ml_dsa_message_mechanism(hash, self.hedging, context))
            }
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

    fn mode_mechanism(&self) -> Result<MechanismType, Error> {
        match self.input {
            HashInput::Message { hash, .. } => message_mechanism_type(hash, true),
            HashInput::Digest { .. } => Ok(MechanismType::HASH_ML_DSA),
        }
    }
}

/// HashSLH-DSA request. Debug omits message, digest and context bytes.
#[derive(Clone, Copy)]
pub struct HashSlhDsaRequest<'a> {
    /// Expected key parameter set.
    pub parameter_set: SlhDsaParameterSet,
    /// Original message or caller digest.
    pub input: HashInput<'a>,
    /// FIPS 205 context, at most 255 bytes.
    pub context: &'a [u8],
    /// Explicit signing randomness requirement; ignored for verification.
    pub hedging: SlhDsaHedging,
}

impl std::fmt::Debug for HashSlhDsaRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashSlhDsaRequest")
            .field("parameter_set", &self.parameter_set)
            .field("input", &self.input)
            .field("hedging", &self.hedging)
            .finish_non_exhaustive()
    }
}

impl HashSlhDsaRequest<'_> {
    /// Validate bounds and the prehash contract before provider access.
    pub fn validate(&self) -> Result<(), Error> {
        if self.context.len() > 255 {
            return Err(Error::InvalidParameters(
                "HashSLH-DSA context exceeds 255 bytes",
            ));
        }
        self.input.validate()?;
        if matches!(self.input, HashInput::Message { message, .. } if message.len() > 64 * 1024 * 1024)
        {
            return Err(Error::InvalidParameters(
                "HashSLH-DSA message exceeds 64 MiB",
            ));
        }
        Ok(())
    }

    fn mechanism(&self) -> Result<Mechanism<'_>, Error> {
        let context = (!self.context.is_empty()).then_some(self.context);
        match self.input {
            HashInput::Message { hash, .. } => {
                Ok(slh_dsa_message_mechanism(hash, self.hedging, context))
            }
            HashInput::Digest { hash, .. } => {
                let hash_mechanism = hash
                    .mechanism()
                    .ok_or(Error::UnsupportedSigning("HashSLH-DSA XOF prehash"))?;
                Ok(Mechanism::HashSlhDsa(HashSignAdditionalContext::new(
                    self.hedging.mechanism(),
                    context,
                    hash_mechanism,
                )))
            }
        }
    }

    fn mode_mechanism(&self) -> Result<MechanismType, Error> {
        match self.input {
            HashInput::Message { hash, .. } => message_mechanism_type(hash, false),
            HashInput::Digest { .. } => Ok(MechanismType::HASH_SLH_DSA),
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

/// HashSLH-DSA signing policy.
#[derive(Clone, Debug)]
pub struct HashSlhDsaSigningPolicy {
    /// Allowed parameter sets.
    pub parameter_sets: Vec<SlhDsaParameterSet>,
    /// Allowed prehash algorithms.
    pub hashes: Vec<PrehashAlgorithm>,
}
impl Default for HashSlhDsaSigningPolicy {
    fn default() -> Self {
        Self {
            parameter_sets: SlhDsaParameterSet::ALL.to_vec(),
            hashes: PrehashAlgorithm::ALL.to_vec(),
        }
    }
}
impl HashSlhDsaSigningPolicy {
    /// Validate policy and request without provider access.
    pub fn validate(&self, request: &HashSlhDsaRequest<'_>) -> Result<(), Error> {
        request.validate()?;
        if !self.parameter_sets.contains(&request.parameter_set)
            || !self.hashes.contains(&request.input.hash())
        {
            return Err(Error::UnsupportedSigning("HashSLH-DSA policy"));
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

/// Advisory HashSLH-DSA signing snapshot for one hash/mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashSlhDsaCapabilities {
    /// Actual key parameter set.
    pub parameter_set: SlhDsaParameterSet,
    /// Prehash algorithm.
    pub hash: PrehashAlgorithm,
    /// Whether the caller supplies a digest.
    pub prehashed: bool,
    /// Key permission, allowed mechanism and token flags agree.
    pub can_sign: bool,
    /// Context authentication is required after init.
    pub always_authenticate: bool,
}

fn ml_dsa_capabilities(
    object: &Object<'_, '_>,
    hash: PrehashAlgorithm,
    prehashed: bool,
) -> Result<HashMlDsaCapabilities, Error> {
    let parameter_set = ml_dsa::parameter_set(object, ObjectClass::PRIVATE_KEY)?;
    let mode = if prehashed {
        MechanismType::HASH_ML_DSA
    } else {
        message_mechanism_type(hash, true)?
    };
    let module = object.session.token().module.raw()?;
    let can_sign = ml_dsa::permission(object, AttributeType::Sign)?
        && ml_dsa::allowed_mechanism(object, mode)?
        && ml_dsa::mechanism_support(object.session.token(), parameter_set, mode, |info| {
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
        always_authenticate: ml_dsa::permission(object, AttributeType::AlwaysAuthenticate)?,
    })
}

fn slh_dsa_capabilities(
    object: &Object<'_, '_>,
    hash: PrehashAlgorithm,
    prehashed: bool,
) -> Result<HashSlhDsaCapabilities, Error> {
    let parameter_set = slh_dsa::parameter_set(object, ObjectClass::PRIVATE_KEY)?;
    let mode = if prehashed {
        MechanismType::HASH_SLH_DSA
    } else {
        message_mechanism_type(hash, false)?
    };
    let module = object.session.token().module.raw()?;
    let can_sign = slh_dsa::permission(object, AttributeType::Sign)?
        && slh_dsa::allowed_mechanism(object, mode)?
        && slh_dsa::mechanism_support(object.session.token(), parameter_set, mode, |info| {
            info.sign()
        })?
        && [Function::SignInit, Function::Sign]
            .into_iter()
            .all(|function| module.is_fn_supported(function));
    Ok(HashSlhDsaCapabilities {
        parameter_set,
        hash,
        prehashed,
        can_sign,
        always_authenticate: slh_dsa::permission(object, AttributeType::AlwaysAuthenticate)?,
    })
}

fn sign_ml_dsa(
    session: &mut Session<'_>,
    key: &PrivateKeyRef,
    request: &HashMlDsaRequest<'_>,
    policy: &HashMlDsaSigningPolicy,
    context_pin: Option<Pin<'_>>,
) -> Result<Vec<u8>, Error> {
    policy.validate(request)?;
    let object = session.resolve(key.as_object_ref())?;
    let caps = ml_dsa_capabilities(&object, request.input.hash(), request.input.is_prehashed())?;
    if caps.parameter_set != request.parameter_set || !caps.can_sign {
        return Err(Error::UnsupportedSigning("HashML-DSA key or permissions"));
    }
    let pin = if caps.always_authenticate {
        object
            .session
            .login_pin(context_pin.ok_or(Error::ContextAuthenticationRequired)?)?
    } else {
        if context_pin.is_some() {
            return Err(Error::InvalidParameters(
                "context PIN for a key without always-authenticate",
            ));
        }
        None
    };
    let mechanism = request.mechanism()?;
    let raw = object.session.raw()?;
    object.session.healthy.set(false);
    let signature = if caps.always_authenticate {
        raw.sign_init(&mechanism, object.handle)
            .map_err(|e| backend("HashML-DSA sign init", e))?;
        raw.login(UserType::ContextSpecific, pin)
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

fn verify_ml_dsa(
    session: &mut Session<'_>,
    key: &PublicKeyRef,
    request: &HashMlDsaRequest<'_>,
    signature: &[u8],
) -> Result<(), Error> {
    request.validate()?;
    if signature.len() != request.parameter_set.signature_length() {
        return Err(Error::SignatureMismatch);
    }
    let object = session.resolve(key.as_object_ref())?;
    let parameter = ml_dsa::parameter_set(&object, ObjectClass::PUBLIC_KEY)?;
    let mode = request.mode_mechanism()?;
    if parameter != request.parameter_set
        || !ml_dsa::permission(&object, AttributeType::Verify)?
        || !ml_dsa::allowed_mechanism(&object, mode)?
        || !ml_dsa::mechanism_support(object.session.token(), parameter, mode, |info| {
            info.verify()
        })?
    {
        return Err(Error::UnsupportedSigning(
            "HashML-DSA verification permissions",
        ));
    }
    let mechanism = request.mechanism()?;
    let raw = object.session.raw()?;
    object.session.healthy.set(false);
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

fn sign_slh_dsa(
    session: &mut Session<'_>,
    key: &PrivateKeyRef,
    request: &HashSlhDsaRequest<'_>,
    policy: &HashSlhDsaSigningPolicy,
    context_pin: Option<Pin<'_>>,
) -> Result<Vec<u8>, Error> {
    policy.validate(request)?;
    let object = session.resolve(key.as_object_ref())?;
    let caps = slh_dsa_capabilities(&object, request.input.hash(), request.input.is_prehashed())?;
    if caps.parameter_set != request.parameter_set || !caps.can_sign {
        return Err(Error::UnsupportedSigning("HashSLH-DSA key or permissions"));
    }
    let pin = if caps.always_authenticate {
        object
            .session
            .login_pin(context_pin.ok_or(Error::ContextAuthenticationRequired)?)?
    } else {
        if context_pin.is_some() {
            return Err(Error::InvalidParameters(
                "context PIN for a key without always-authenticate",
            ));
        }
        None
    };
    let mechanism = request.mechanism()?;
    let raw = object.session.raw()?;
    object.session.healthy.set(false);
    let signature = if caps.always_authenticate {
        raw.sign_init(&mechanism, object.handle)
            .map_err(|e| backend("HashSLH-DSA sign init", e))?;
        raw.login(UserType::ContextSpecific, pin)
            .map_err(|e| backend("HashSLH-DSA context login", e))?;
        raw.sign_update(request.input.bytes())
            .map_err(|e| backend("HashSLH-DSA sign update", e))?;
        raw.sign_final()
            .map_err(|e| backend("HashSLH-DSA sign final", e))?
    } else {
        raw.sign(&mechanism, object.handle, request.input.bytes())
            .map_err(|e| backend("HashSLH-DSA sign", e))?
    };
    if signature.len() != request.parameter_set.signature_length() {
        return Err(Error::InvalidSignature);
    }
    object.session.healthy.set(true);
    Ok(signature)
}

fn verify_slh_dsa(
    session: &mut Session<'_>,
    key: &PublicKeyRef,
    request: &HashSlhDsaRequest<'_>,
    signature: &[u8],
) -> Result<(), Error> {
    request.validate()?;
    if signature.len() != request.parameter_set.signature_length() {
        return Err(Error::SignatureMismatch);
    }
    let object = session.resolve(key.as_object_ref())?;
    let parameter = slh_dsa::parameter_set(&object, ObjectClass::PUBLIC_KEY)?;
    let mode = request.mode_mechanism()?;
    if parameter != request.parameter_set
        || !slh_dsa::permission(&object, AttributeType::Verify)?
        || !slh_dsa::allowed_mechanism(&object, mode)?
        || !slh_dsa::mechanism_support(object.session.token(), parameter, mode, |info| {
            info.verify()
        })?
    {
        return Err(Error::UnsupportedSigning(
            "HashSLH-DSA verification permissions",
        ));
    }
    let mechanism = request.mechanism()?;
    let raw = object.session.raw()?;
    object.session.healthy.set(false);
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
            backend("HashSLH-DSA verify", error),
            Error::UnsupportedVerification("HashSLH-DSA verification unavailable"),
        )),
    }
}

impl Session<'_> {
    /// Inspect a private key's HashML-DSA signing support for one hash/mode.
    pub fn hash_ml_dsa_capabilities(
        &mut self,
        key: &PrivateKeyRef,
        hash: PrehashAlgorithm,
        prehashed: bool,
    ) -> Result<HashMlDsaCapabilities, Error> {
        ml_dsa_capabilities(&self.resolve(key.as_object_ref())?, hash, prehashed)
    }

    /// Sign one HashML-DSA message or digest.
    pub fn sign_hash_ml_dsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &HashMlDsaRequest<'_>,
        policy: &HashMlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        sign_ml_dsa(self, key, request, policy, context_pin)
    }

    /// Verify one HashML-DSA signature on the token.
    pub fn verify_hash_ml_dsa(
        &mut self,
        key: &PublicKeyRef,
        request: &HashMlDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        verify_ml_dsa(self, key, request, signature)
    }

    /// Inspect a private key's HashSLH-DSA signing support for one hash/mode.
    pub fn hash_slh_dsa_capabilities(
        &mut self,
        key: &PrivateKeyRef,
        hash: PrehashAlgorithm,
        prehashed: bool,
    ) -> Result<HashSlhDsaCapabilities, Error> {
        slh_dsa_capabilities(&self.resolve(key.as_object_ref())?, hash, prehashed)
    }

    /// Sign one HashSLH-DSA message or digest.
    pub fn sign_hash_slh_dsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &HashSlhDsaRequest<'_>,
        policy: &HashSlhDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        sign_slh_dsa(self, key, request, policy, context_pin)
    }

    /// Verify one HashSLH-DSA signature on the token.
    pub fn verify_hash_slh_dsa(
        &mut self,
        key: &PublicKeyRef,
        request: &HashSlhDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        verify_slh_dsa(self, key, request, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prehash_lengths_and_xof_boundaries_are_explicit() {
        for (hash, length, xof) in [
            (PrehashAlgorithm::Sha224, 28, false),
            (PrehashAlgorithm::Sha256, 32, false),
            (PrehashAlgorithm::Sha384, 48, false),
            (PrehashAlgorithm::Sha512, 64, false),
            (PrehashAlgorithm::Sha3_224, 28, false),
            (PrehashAlgorithm::Sha3_256, 32, false),
            (PrehashAlgorithm::Sha3_384, 48, false),
            (PrehashAlgorithm::Sha3_512, 64, false),
            (PrehashAlgorithm::Shake128, 32, true),
            (PrehashAlgorithm::Shake256, 64, true),
        ] {
            assert_eq!(hash.output_len(), length);
            assert_eq!(hash.is_xof(), xof);
            assert_eq!(
                hash.mechanism().is_some(),
                matches!(
                    hash,
                    PrehashAlgorithm::Sha224
                        | PrehashAlgorithm::Sha256
                        | PrehashAlgorithm::Sha384
                        | PrehashAlgorithm::Sha512
                )
            );
        }
    }

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
