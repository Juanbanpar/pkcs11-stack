// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AttributeType, DigestAlgorithm, Error, MechanismType, Object, ObjectClass, Pin, PrivateKeyRef,
    PublicKeyRef, SLH_DSA_MAXIMUM_MESSAGE, Session, SlhDsaHedging, SlhDsaKeyPairRequest,
    SlhDsaParameterSet, error::backend, slh_dsa,
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

/// Explicit single-part HashSLH-DSA input contract. No mode substitutes for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashSlhDsaMode {
    /// Original message, hashed on the token by `CKM_HASH_SLH_DSA_<hash>`.
    Message(DigestAlgorithm),
    /// Exactly one digest, passed unchanged to CKM_HASH_SLH_DSA.
    Prehashed(DigestAlgorithm),
}
impl HashSlhDsaMode {
    /// The prehash algorithm, independent of the SLH-DSA parameter set's internal hash.
    pub fn hash(self) -> DigestAlgorithm {
        match self {
            Self::Message(hash) | Self::Prehashed(hash) => hash,
        }
    }
    /// Whether the caller supplies a digest instead of an original message.
    pub fn is_prehashed(self) -> bool {
        matches!(self, Self::Prehashed(_))
    }
    fn mechanism_type(self) -> MechanismType {
        if self.is_prehashed() {
            return MechanismType::HASH_SLH_DSA;
        }
        match self.hash() {
            DigestAlgorithm::Sha224 => MechanismType::HASH_SLH_DSA_SHA224,
            DigestAlgorithm::Sha256 => MechanismType::HASH_SLH_DSA_SHA256,
            DigestAlgorithm::Sha384 => MechanismType::HASH_SLH_DSA_SHA384,
            DigestAlgorithm::Sha512 => MechanismType::HASH_SLH_DSA_SHA512,
            DigestAlgorithm::Sha3_224 => MechanismType::HASH_SLH_DSA_SHA3_224,
            DigestAlgorithm::Sha3_256 => MechanismType::HASH_SLH_DSA_SHA3_256,
            DigestAlgorithm::Sha3_384 => MechanismType::HASH_SLH_DSA_SHA3_384,
            DigestAlgorithm::Sha3_512 => MechanismType::HASH_SLH_DSA_SHA3_512,
        }
    }
}
/// Borrowed original message or fixed-length digest. Debug omits input bytes.
#[derive(Clone, Copy)]
pub enum HashSlhDsaInput<'a> {
    /// Hash the original message on the token, including the empty message.
    Message {
        /// Explicit prehash algorithm.
        hash: DigestAlgorithm,
        /// Original message, at most 64 MiB.
        message: &'a [u8],
    },
    /// Supply an already computed digest; the runtime never hashes it again.
    Digest {
        /// Algorithm used by the caller to compute the digest.
        hash: DigestAlgorithm,
        /// Exactly hash.output_len() bytes.
        bytes: &'a [u8],
    },
}
impl<'a> HashSlhDsaInput<'a> {
    /// Exact native input contract.
    pub fn mode(self) -> HashSlhDsaMode {
        match self {
            Self::Message { hash, .. } => HashSlhDsaMode::Message(hash),
            Self::Digest { hash, .. } => HashSlhDsaMode::Prehashed(hash),
        }
    }
    /// Borrow the input unchanged.
    pub fn bytes(self) -> &'a [u8] {
        match self {
            Self::Message { message, .. } => message,
            Self::Digest { bytes, .. } => bytes,
        }
    }
}
impl std::fmt::Debug for HashSlhDsaInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashSlhDsaInput")
            .field("mode", &self.mode())
            .finish_non_exhaustive()
    }
}
/// HashSLH-DSA with explicit prehash, context and signing randomness requirements.
/// This signature domain is distinct from pure SLH-DSA. Debug omits all input bytes.
#[derive(Clone, Copy)]
pub struct HashSlhDsaRequest<'a> {
    /// Expected key parameter set.
    pub parameter_set: SlhDsaParameterSet,
    /// Original message or caller-provided digest, never inferred from its length.
    pub input: HashSlhDsaInput<'a>,
    /// FIPS 205 domain-separation context, at most 255 bytes.
    pub context: &'a [u8],
    /// Explicit randomness requirement; ignored during verification.
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
    /// Check message/context limits and exact digest length before native access.
    pub fn validate(&self) -> Result<(), Error> {
        if self.context.len() > 255 {
            return Err(Error::InvalidParameters(
                "HashSLH-DSA context exceeds 255 bytes",
            ));
        }
        match self.input {
            HashSlhDsaInput::Message { message, .. } if message.len() > SLH_DSA_MAXIMUM_MESSAGE => {
                Err(Error::InvalidParameters(
                    "HashSLH-DSA message exceeds 64 MiB",
                ))
            }
            HashSlhDsaInput::Digest { hash, bytes } if bytes.len() != hash.output_len() => {
                Err(Error::InvalidParameters("HashSLH-DSA digest length"))
            }
            _ => Ok(()),
        }
    }
    fn mechanism(&self) -> Mechanism<'_> {
        let context = (!self.context.is_empty()).then_some(self.context);
        let mode = self.input.mode();
        if mode.is_prehashed() {
            return Mechanism::HashSlhDsa(HashSignAdditionalContext::new(
                self.hedging.mechanism(),
                context,
                mode.hash().mechanism(),
            ));
        }
        let parameters = SignAdditionalContext::new(self.hedging.mechanism(), context);
        match mode.hash() {
            DigestAlgorithm::Sha224 => Mechanism::HashSlhDsaSha224(parameters),
            DigestAlgorithm::Sha256 => Mechanism::HashSlhDsaSha256(parameters),
            DigestAlgorithm::Sha384 => Mechanism::HashSlhDsaSha384(parameters),
            DigestAlgorithm::Sha512 => Mechanism::HashSlhDsaSha512(parameters),
            DigestAlgorithm::Sha3_224 => Mechanism::HashSlhDsaSha3_224(parameters),
            DigestAlgorithm::Sha3_256 => Mechanism::HashSlhDsaSha3_256(parameters),
            DigestAlgorithm::Sha3_384 => Mechanism::HashSlhDsaSha3_384(parameters),
            DigestAlgorithm::Sha3_512 => Mechanism::HashSlhDsaSha3_512(parameters),
        }
    }
}
/// Separate opt-in policy for HashSLH-DSA. Does not enable pure or classical signing.
#[derive(Clone, Debug)]
pub struct HashSlhDsaSigningPolicy {
    /// Allowed key parameter sets. An empty list disables signing.
    pub parameter_sets: Vec<SlhDsaParameterSet>,
    /// Allowed prehash algorithms. An empty list disables signing.
    pub hashes: Vec<DigestAlgorithm>,
    /// Permit a prehash shorter than 2n bytes, reducing the claimed parameter-set
    /// strength. False by default, following FIPS 205 section 10.2. SHA-224 and
    /// SHA3-224 require this explicit compatibility choice for every parameter set.
    pub allow_reduced_strength: bool,
}
impl Default for HashSlhDsaSigningPolicy {
    fn default() -> Self {
        Self {
            parameter_sets: SlhDsaParameterSet::ALL.to_vec(),
            hashes: HASHES.to_vec(),
            allow_reduced_strength: false,
        }
    }
}
impl HashSlhDsaSigningPolicy {
    /// Validate input, parameter set and prehash policy without authentication or native calls.
    pub fn validate(&self, request: &HashSlhDsaRequest<'_>) -> Result<(), Error> {
        request.validate()?;
        if !self.parameter_sets.contains(&request.parameter_set)
            || !self.hashes.contains(&request.input.mode().hash())
        {
            return Err(Error::UnsupportedSigning(
                "HashSLH-DSA parameter set or hash policy",
            ));
        }
        if !self.allow_reduced_strength
            && request.input.mode().hash().output_len() < request.parameter_set.public_key_length()
        {
            return Err(Error::UnsupportedSigning(
                "HashSLH-DSA prehash reduces parameter-set strength",
            ));
        }
        Ok(())
    }
}
const HASHES: [DigestAlgorithm; 8] = [
    DigestAlgorithm::Sha224,
    DigestAlgorithm::Sha256,
    DigestAlgorithm::Sha384,
    DigestAlgorithm::Sha512,
    DigestAlgorithm::Sha3_224,
    DigestAlgorithm::Sha3_256,
    DigestAlgorithm::Sha3_384,
    DigestAlgorithm::Sha3_512,
];
impl<'m> Session<'m> {
    /// Generate a persistent, sensitive, nonextractable HashSLH-DSA signing pair.
    /// Uses the same ID, label, authentication and duplicate checks as pure generation.
    /// Both keys permit only CKM_HASH_SLH_DSA and the eight fixed-output SHA2/SHA3
    /// combined mechanisms. Pure SLH-DSA and SHAKE prehash are excluded.
    /// The raw mechanism's hash parameter is enforced by application policy, not
    /// CKA_ALLOWED_MECHANISMS. Requires RW mode; provider effects are not retried or rolled back.
    pub fn generate_hash_slh_dsa_key_pair(
        &mut self,
        request: &SlhDsaKeyPairRequest<'_>,
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        let mut mechanisms = vec![MechanismType::HASH_SLH_DSA];
        mechanisms.extend(HASHES.map(|hash| HashSlhDsaMode::Message(hash).mechanism_type()));
        self.generate_slh_dsa_pair(request, &mechanisms)
    }
}

/// Advisory native single-part signing snapshot for one HashSLH-DSA hash/input mode.
/// Application policy is checked separately before each signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashSlhDsaCapabilities {
    /// Actual key parameter set.
    pub parameter_set: SlhDsaParameterSet,
    /// Exact input contract and mechanism checked by this snapshot.
    pub mode: HashSlhDsaMode,
    /// Permission, allowed mechanism, native entry points and token flags/bounds agree.
    pub can_sign: bool,
    /// Context-specific authentication is required after signing initialization.
    pub always_authenticate: bool,
}
impl HashSlhDsaCapabilities {
    /// Validate the mode, parameter set and policy without executing a signature.
    pub fn validate(
        &self,
        request: &HashSlhDsaRequest<'_>,
        policy: &HashSlhDsaSigningPolicy,
    ) -> Result<(), Error> {
        policy.validate(request)?;
        if self.parameter_set != request.parameter_set
            || self.mode.hash() != request.input.mode().hash()
            || self.mode.is_prehashed() != request.input.mode().is_prehashed()
            || !self.can_sign
        {
            return Err(Error::UnsupportedSigning(
                "HashSLH-DSA key, mode or token permissions",
            ));
        }
        Ok(())
    }
}

fn capabilities(
    object: &crate::Object<'_, '_>,
    mode: HashSlhDsaMode,
) -> Result<HashSlhDsaCapabilities, Error> {
    let parameter_set = slh_dsa::parameter_set(object, ObjectClass::PRIVATE_KEY)?;
    let always_authenticate = slh_dsa::permission(object, AttributeType::AlwaysAuthenticate)?;
    let module = object.session.token().module.raw()?;
    let can_sign = slh_dsa::permission(object, AttributeType::Sign)?
        && slh_dsa::allowed_mechanism(object, mode.mechanism_type())?
        && slh_dsa::mechanism_support(
            object.session.token(),
            parameter_set,
            mode.mechanism_type(),
            |i| i.sign(),
        )?
        && [Function::SignInit, Function::Sign]
            .iter()
            .all(|&f| module.is_fn_supported(f))
        && (!always_authenticate || module.is_fn_supported(Function::Login));
    Ok(HashSlhDsaCapabilities {
        parameter_set,
        mode,
        can_sign,
        always_authenticate,
    })
}

fn verification_key(
    object: &crate::Object<'_, '_>,
    mode: HashSlhDsaMode,
) -> Result<(SlhDsaParameterSet, bool), Error> {
    let parameter = slh_dsa::parameter_set(object, ObjectClass::PUBLIC_KEY)?;
    let permitted = slh_dsa::permission(object, AttributeType::Verify)?
        && slh_dsa::allowed_mechanism(object, mode.mechanism_type())?
        && slh_dsa::mechanism_support(
            object.session.token(),
            parameter,
            mode.mechanism_type(),
            |i| i.verify(),
        )?;
    Ok((parameter, permitted))
}

impl Session<'_> {
    /// Discover one key's single-part HashSLH-DSA signing support for one hash/input mode.
    /// Modes are checked independently and never substituted for one another.
    pub fn hash_slh_dsa_capabilities(
        &mut self,
        key: &PrivateKeyRef,
        mode: HashSlhDsaMode,
    ) -> Result<HashSlhDsaCapabilities, Error> {
        capabilities(&self.resolve(key.as_object_ref())?, mode)
    }

    /// Sign once with bounded output after rediscovering current permissions.
    /// Always-authenticate uses init, context login, then C_Sign; prehash never
    /// uses multipart calls. Backend errors/unwinds discard the session; no retry.
    pub fn sign_hash_slh_dsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &HashSlhDsaRequest<'_>,
        policy: &HashSlhDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        let result = self.sign_hash_slh_dsa_once(key, request, policy, context_pin);
        if matches!(
            &result,
            Err(Error::Backend { .. } | Error::TokenChanged | Error::InvalidSignature)
        ) {
            self.healthy.set(false);
        }
        result
    }
    fn sign_hash_slh_dsa_once(
        &mut self,
        key: &PrivateKeyRef,
        request: &HashSlhDsaRequest<'_>,
        policy: &HashSlhDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        policy.validate(request)?;
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
            .map_err(|e| backend("HashSLH-DSA sign init", e))?;
        if caps.always_authenticate {
            raw.login(UserType::ContextSpecific, pin)
                .map_err(|e| backend("HashSLH-DSA context login", e))?;
        }
        let written = raw
            .sign_initialized_into(request.input.bytes(), &mut signature)
            .map_err(|e| backend("HashSLH-DSA sign", e))?;
        if written != signature.len() {
            return Err(Error::InvalidSignature);
        }
        object.session.healthy.set(true);
        Ok(signature)
    }

    /// Verify once on the token. Only a completed C_Verify mismatch restores
    /// session reuse; initialization errors and other native failures discard it.
    pub fn verify_hash_slh_dsa(
        &mut self,
        key: &PublicKeyRef,
        request: &HashSlhDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        let result = self.verify_hash_slh_dsa_once(key, request, signature);
        if matches!(&result, Err(Error::Backend { .. } | Error::TokenChanged)) {
            self.healthy.set(false);
        }
        result
    }
    fn verify_hash_slh_dsa_once(
        &mut self,
        key: &PublicKeyRef,
        request: &HashSlhDsaRequest<'_>,
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
                "HashSLH-DSA verification permissions or parameter set",
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
            Err(error) => Err(backend("HashSLH-DSA verify", error)),
        }
    }
}
