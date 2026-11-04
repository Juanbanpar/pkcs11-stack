// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AttributeType, DigestAlgorithm, Error, MechanismType, MlDsaHedging, MlDsaParameterSet,
    MlDsaSigningPolicy, ObjectClass, Pin, PrivateKeyRef, PublicKeyRef, Session, error::backend,
    ml_dsa,
};
use cryptoki::{
    context::Function,
    error::{Error as CryptokiError, RvError},
    mechanism::{
        Mechanism,
        dsa::{HashSignAdditionalContext, SignAdditionalContext},
    },
    session::UserType,
};

/// Native HashML-DSA input contract. Legacy variants select SHA-512.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashMlDsaMode {
    /// Original message, hashed on the token by CKM_HASH_ML_DSA_SHA512.
    Message,
    /// Already computed 64-byte SHA-512 digest, supplied to CKM_HASH_ML_DSA.
    Prehashed,
    /// Original message hashed on the token with an explicit fixed-output hash.
    MessageWithHash(DigestAlgorithm),
    /// Caller-computed digest with an explicit fixed-output hash; single-part only.
    PrehashedWithHash(DigestAlgorithm),
}
impl HashMlDsaMode {
    /// Select token-side hashing, retaining the legacy SHA-512 mode value.
    pub fn message(hash: DigestAlgorithm) -> Self {
        if hash == DigestAlgorithm::Sha512 {
            Self::Message
        } else {
            Self::MessageWithHash(hash)
        }
    }
    /// Select caller-side hashing, retaining the legacy SHA-512 mode value.
    pub fn prehashed(hash: DigestAlgorithm) -> Self {
        if hash == DigestAlgorithm::Sha512 {
            Self::Prehashed
        } else {
            Self::PrehashedWithHash(hash)
        }
    }
    /// Exact hash selected by this profile; equal output lengths remain distinct.
    pub fn hash(self) -> DigestAlgorithm {
        match self {
            Self::Message | Self::Prehashed => DigestAlgorithm::Sha512,
            Self::MessageWithHash(hash) | Self::PrehashedWithHash(hash) => hash,
        }
    }
    /// Whether input is an already computed digest, which cannot be streamed.
    pub fn is_prehashed(self) -> bool {
        matches!(self, Self::Prehashed | Self::PrehashedWithHash(_))
    }
    pub(crate) fn mechanism_type(self) -> MechanismType {
        if self.is_prehashed() {
            return MechanismType::HASH_ML_DSA;
        }
        match self.hash() {
            DigestAlgorithm::Sha224 => MechanismType::HASH_ML_DSA_SHA224,
            DigestAlgorithm::Sha256 => MechanismType::HASH_ML_DSA_SHA256,
            DigestAlgorithm::Sha384 => MechanismType::HASH_ML_DSA_SHA384,
            DigestAlgorithm::Sha512 => MechanismType::HASH_ML_DSA_SHA512,
            DigestAlgorithm::Sha3_224 => MechanismType::HASH_ML_DSA_SHA3_224,
            DigestAlgorithm::Sha3_256 => MechanismType::HASH_ML_DSA_SHA3_256,
            DigestAlgorithm::Sha3_384 => MechanismType::HASH_ML_DSA_SHA3_384,
            DigestAlgorithm::Sha3_512 => MechanismType::HASH_ML_DSA_SHA3_512,
        }
    }
}

/// Original message or caller digest; legacy variants use SHA-512. Debug omits input bytes.
#[derive(Clone, Copy)]
pub enum HashMlDsaInput<'a> {
    /// Original message; empty input is valid.
    Message(&'a [u8]),
    /// Exactly 64 bytes computed with SHA-512 by the caller.
    Sha512Digest(&'a [u8; 64]),
    /// Original message hashed on the token with the selected SHA-2/SHA-3 hash.
    MessageWithHash {
        /// Fixed-output hash used by the native combined mechanism.
        hash: DigestAlgorithm,
        /// Original message; empty input is valid.
        message: &'a [u8],
    },
    /// Caller-computed SHA-2/SHA-3 digest. Request validation checks its exact length.
    Digest {
        /// Exact digest algorithm, including FIPS 204's prehash domain separation.
        hash: DigestAlgorithm,
        /// Exactly hash.output_len() bytes; no software hashing or truncation occurs.
        bytes: &'a [u8],
    },
}
impl<'a> HashMlDsaInput<'a> {
    /// Native mechanism required by this input, without provider access.
    pub fn mode(self) -> HashMlDsaMode {
        match self {
            Self::Message(_) => HashMlDsaMode::Message,
            Self::Sha512Digest(_) => HashMlDsaMode::Prehashed,
            Self::MessageWithHash { hash, .. } => HashMlDsaMode::message(hash),
            Self::Digest { hash, .. } => HashMlDsaMode::prehashed(hash),
        }
    }
    pub(crate) fn bytes(self) -> &'a [u8] {
        match self {
            Self::Message(bytes) => bytes,
            Self::Sha512Digest(bytes) => bytes,
            Self::MessageWithHash { message, .. } => message,
            Self::Digest { bytes, .. } => bytes,
        }
    }
}
impl std::fmt::Debug for HashMlDsaInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HashMlDsaInput").field(&self.mode()).finish()
    }
}

/// Fixed-output SHA-2/SHA-3 HashML-DSA request, distinct from pure ML-DSA and external-mu input.
/// Debug omits input and context bytes. No private material is read.
#[derive(Clone, Copy)]
pub struct HashMlDsaRequest<'a> {
    /// Expected key parameter set, rediscovered before execution.
    pub parameter_set: MlDsaParameterSet,
    /// Original message or caller-computed digest; legacy variants select SHA-512.
    pub input: HashMlDsaInput<'a>,
    /// FIPS 204 context, at most 255 bytes.
    pub context: &'a [u8],
    /// Explicit signing randomness requirement; ignored for verification.
    pub hedging: MlDsaHedging,
}
impl std::fmt::Debug for HashMlDsaRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashMlDsaRequest")
            .field("parameter_set", &self.parameter_set)
            .field("mode", &self.input.mode())
            .field("hedging", &self.hedging)
            .finish_non_exhaustive()
    }
}
impl HashMlDsaRequest<'_> {
    /// Check context and exact caller-digest lengths without provider access.
    pub fn validate(&self) -> Result<(), Error> {
        if self.context.len() > 255 {
            return Err(Error::InvalidParameters(
                "HashML-DSA context exceeds 255 bytes",
            ));
        }
        if let HashMlDsaInput::Digest { hash, bytes } = self.input {
            if bytes.len() != hash.output_len() {
                return Err(Error::InvalidParameters("HashML-DSA digest length"));
            }
        }
        Ok(())
    }
    pub(crate) fn mechanism(&self) -> Mechanism<'_> {
        let context = (!self.context.is_empty()).then_some(self.context);
        let mode = self.input.mode();
        if mode.is_prehashed() {
            return Mechanism::HashMlDsa(HashSignAdditionalContext::new(
                self.hedging.mechanism(),
                context,
                mode.hash().mechanism(),
            ));
        }
        let parameters = SignAdditionalContext::new(self.hedging.mechanism(), context);
        match mode.hash() {
            DigestAlgorithm::Sha224 => Mechanism::HashMlDsaSha224(parameters),
            DigestAlgorithm::Sha256 => Mechanism::HashMlDsaSha256(parameters),
            DigestAlgorithm::Sha384 => Mechanism::HashMlDsaSha384(parameters),
            DigestAlgorithm::Sha512 => Mechanism::HashMlDsaSha512(parameters),
            DigestAlgorithm::Sha3_224 => Mechanism::HashMlDsaSha3_224(parameters),
            DigestAlgorithm::Sha3_256 => Mechanism::HashMlDsaSha3_256(parameters),
            DigestAlgorithm::Sha3_384 => Mechanism::HashMlDsaSha3_384(parameters),
            DigestAlgorithm::Sha3_512 => Mechanism::HashMlDsaSha3_512(parameters),
        }
    }
}
impl MlDsaSigningPolicy {
    /// Apply the ML-DSA parameter-set policy to an explicit HashML-DSA request.
    pub fn validate_hash_ml_dsa(&self, request: &HashMlDsaRequest<'_>) -> Result<(), Error> {
        request.validate()?;
        if !self.parameter_sets.contains(&request.parameter_set) {
            return Err(Error::UnsupportedSigning("HashML-DSA parameter set policy"));
        }
        Ok(())
    }
}

/// Advisory signing snapshot for one HashML-DSA mode. The discovery method
/// selects the single-part or multipart entry-point requirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashMlDsaCapabilities {
    /// Actual key parameter set.
    pub parameter_set: MlDsaParameterSet,
    /// Exact input contract and mechanism checked by this snapshot.
    pub mode: HashMlDsaMode,
    /// Permission, allowed mechanism, native entry points and token flags/bounds agree.
    pub can_sign: bool,
    /// Context-specific authentication is required after signing initialization.
    pub always_authenticate: bool,
}
impl HashMlDsaCapabilities {
    /// Validate the mode, parameter set and policy without executing a signature.
    pub fn validate(
        &self,
        request: &HashMlDsaRequest<'_>,
        policy: &MlDsaSigningPolicy,
    ) -> Result<(), Error> {
        policy.validate_hash_ml_dsa(request)?;
        if self.parameter_set != request.parameter_set
            || self.mode.hash() != request.input.mode().hash()
            || self.mode.is_prehashed() != request.input.mode().is_prehashed()
            || !self.can_sign
        {
            return Err(Error::UnsupportedSigning(
                "HashML-DSA key, mode or token permissions",
            ));
        }
        Ok(())
    }
}

fn capabilities(
    object: &crate::Object<'_, '_>,
    mode: HashMlDsaMode,
) -> Result<HashMlDsaCapabilities, Error> {
    capabilities_with_functions(object, mode, &[Function::SignInit, Function::Sign])
}
pub(crate) fn capabilities_with_functions(
    object: &crate::Object<'_, '_>,
    mode: HashMlDsaMode,
    functions: &[Function],
) -> Result<HashMlDsaCapabilities, Error> {
    let parameter_set = ml_dsa::parameter_set(object, ObjectClass::PRIVATE_KEY)?;
    let always_authenticate = ml_dsa::permission(object, AttributeType::AlwaysAuthenticate)?;
    let module = object.session.token().module.raw()?;
    let can_sign = ml_dsa::permission(object, AttributeType::Sign)?
        && ml_dsa::allowed_mechanism(object, mode.mechanism_type())?
        && ml_dsa::mechanism_support(
            object.session.token(),
            parameter_set,
            mode.mechanism_type(),
            |i| i.sign(),
        )?
        && functions.iter().all(|&f| module.is_fn_supported(f))
        && (!always_authenticate || module.is_fn_supported(Function::Login));
    Ok(HashMlDsaCapabilities {
        parameter_set,
        mode,
        can_sign,
        always_authenticate,
    })
}

pub(crate) fn verification_key(
    object: &crate::Object<'_, '_>,
    mode: HashMlDsaMode,
) -> Result<(MlDsaParameterSet, bool), Error> {
    let parameter = ml_dsa::parameter_set(object, ObjectClass::PUBLIC_KEY)?;
    let permitted = ml_dsa::permission(object, AttributeType::Verify)?
        && ml_dsa::allowed_mechanism(object, mode.mechanism_type())?
        && ml_dsa::mechanism_support(
            object.session.token(),
            parameter,
            mode.mechanism_type(),
            |i| i.verify(),
        )?;
    Ok((parameter, permitted))
}

impl Session<'_> {
    /// Discover one key's single-part HashML-DSA signing support for one hash/input mode.
    /// Modes are checked independently and never substituted for one another.
    pub fn hash_ml_dsa_capabilities(
        &mut self,
        key: &PrivateKeyRef,
        mode: HashMlDsaMode,
    ) -> Result<HashMlDsaCapabilities, Error> {
        capabilities(&self.resolve(key.as_object_ref())?, mode)
    }

    /// Sign once with bounded output after rediscovering current permissions.
    /// Always-authenticate uses init, context login, then C_Sign; prehash never
    /// uses multipart calls. Backend errors/unwinds discard the session; no retry.
    pub fn sign_hash_ml_dsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &HashMlDsaRequest<'_>,
        policy: &MlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        let result = self.sign_hash_ml_dsa_once(key, request, policy, context_pin);
        if matches!(
            &result,
            Err(Error::Backend { .. } | Error::TokenChanged | Error::InvalidSignature)
        ) {
            self.healthy.set(false);
        }
        result
    }
    fn sign_hash_ml_dsa_once(
        &mut self,
        key: &PrivateKeyRef,
        request: &HashMlDsaRequest<'_>,
        policy: &MlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        policy.validate_hash_ml_dsa(request)?;
        let object = self.resolve(key.as_object_ref())?;
        let caps = capabilities(&object, request.input.mode())?;
        caps.validate(request, policy)?;
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
        let mechanism = request.mechanism();
        let raw = object.session.raw()?;
        let mut signature = vec![0; request.parameter_set.signature_length()];
        object.session.healthy.set(false);
        raw.sign_init(&mechanism, object.handle)
            .map_err(|e| backend("HashML-DSA sign init", e))?;
        if caps.always_authenticate {
            raw.login(UserType::ContextSpecific, pin)
                .map_err(|e| backend("HashML-DSA context login", e))?;
        }
        let written = raw
            .sign_initialized_into(request.input.bytes(), &mut signature)
            .map_err(|e| backend("HashML-DSA sign", e))?;
        if written != signature.len() {
            return Err(Error::InvalidSignature);
        }
        object.session.healthy.set(true);
        Ok(signature)
    }

    /// Verify once on the token. Only a completed C_Verify mismatch restores
    /// session reuse; initialization errors and other native failures discard it.
    pub fn verify_hash_ml_dsa(
        &mut self,
        key: &PublicKeyRef,
        request: &HashMlDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        let result = self.verify_hash_ml_dsa_once(key, request, signature);
        if matches!(&result, Err(Error::Backend { .. } | Error::TokenChanged)) {
            self.healthy.set(false);
        }
        result
    }
    fn verify_hash_ml_dsa_once(
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
        let (parameter, permitted) = verification_key(&object, request.input.mode())?;
        let module = object.session.token().module.raw()?;
        if parameter != request.parameter_set
            || !permitted
            || ![Function::VerifyInit, Function::Verify]
                .into_iter()
                .all(|f| module.is_fn_supported(f))
        {
            return Err(Error::UnsupportedSigning(
                "HashML-DSA verification permissions or parameter set",
            ));
        }
        let mechanism = request.mechanism();
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
            Err(error) => Err(backend("HashML-DSA verify", error)),
        }
    }
}
