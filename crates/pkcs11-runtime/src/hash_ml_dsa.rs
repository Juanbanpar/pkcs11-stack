// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AttributeType, Error, MechanismType, MlDsaHedging, MlDsaParameterSet, MlDsaSigningPolicy,
    ObjectClass, Pin, PrivateKeyRef, PublicKeyRef, Session, error::backend, ml_dsa,
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

/// Native SHA-512 HashML-DSA input contract. No implicit hashing or fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashMlDsaMode {
    /// Original message, hashed on the token by CKM_HASH_ML_DSA_SHA512.
    Message,
    /// Already computed 64-byte SHA-512 digest, supplied to CKM_HASH_ML_DSA.
    Prehashed,
}
impl HashMlDsaMode {
    pub(crate) fn mechanism_type(self) -> MechanismType {
        match self {
            Self::Message => MechanismType::HASH_ML_DSA_SHA512,
            Self::Prehashed => MechanismType::HASH_ML_DSA,
        }
    }
}

/// Original message or a SHA-512 digest. Debug omits input bytes.
#[derive(Clone, Copy)]
pub enum HashMlDsaInput<'a> {
    /// Original message; empty input is valid.
    Message(&'a [u8]),
    /// Exactly 64 bytes computed with SHA-512 by the caller.
    Sha512Digest(&'a [u8; 64]),
}
impl<'a> HashMlDsaInput<'a> {
    /// Native mechanism required by this input, without provider access.
    pub fn mode(self) -> HashMlDsaMode {
        match self {
            Self::Message(_) => HashMlDsaMode::Message,
            Self::Sha512Digest(_) => HashMlDsaMode::Prehashed,
        }
    }
    pub(crate) fn bytes(self) -> &'a [u8] {
        match self {
            Self::Message(bytes) => bytes,
            Self::Sha512Digest(bytes) => bytes,
        }
    }
}
impl std::fmt::Debug for HashMlDsaInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HashMlDsaInput").field(&self.mode()).finish()
    }
}

/// SHA-512 HashML-DSA request, distinct from pure ML-DSA and external-mu input.
/// Debug omits input and context bytes. No private material is read.
#[derive(Clone, Copy)]
pub struct HashMlDsaRequest<'a> {
    /// Expected key parameter set, rediscovered before execution.
    pub parameter_set: MlDsaParameterSet,
    /// Original message or caller-computed SHA-512 digest.
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
    /// Check the context bound without provider access. Digest length is typed.
    pub fn validate(&self) -> Result<(), Error> {
        if self.context.len() > 255 {
            return Err(Error::InvalidParameters(
                "HashML-DSA context exceeds 255 bytes",
            ));
        }
        Ok(())
    }
    fn mechanism(&self) -> Mechanism<'_> {
        let context = (!self.context.is_empty()).then_some(self.context);
        match self.input.mode() {
            HashMlDsaMode::Message => Mechanism::HashMlDsaSha512(SignAdditionalContext::new(
                self.hedging.mechanism(),
                context,
            )),
            HashMlDsaMode::Prehashed => Mechanism::HashMlDsa(HashSignAdditionalContext::new(
                self.hedging.mechanism(),
                context,
                MechanismType::SHA512,
            )),
        }
    }
}
impl MlDsaSigningPolicy {
    /// Apply the ML-DSA parameter-set policy to an explicit SHA-512 HashML-DSA request.
    pub fn validate_hash_ml_dsa(&self, request: &HashMlDsaRequest<'_>) -> Result<(), Error> {
        request.validate()?;
        if !self.parameter_sets.contains(&request.parameter_set) {
            return Err(Error::UnsupportedSigning("HashML-DSA parameter set policy"));
        }
        Ok(())
    }
}

/// Advisory single-part signing snapshot for one selected HashML-DSA mode.
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
            || self.mode != request.input.mode()
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
        && [Function::SignInit, Function::Sign]
            .into_iter()
            .all(|f| module.is_fn_supported(f))
        && (!always_authenticate || module.is_fn_supported(Function::Login));
    Ok(HashMlDsaCapabilities {
        parameter_set,
        mode,
        can_sign,
        always_authenticate,
    })
}

impl Session<'_> {
    /// Discover one key's single-part SHA-512 HashML-DSA signing support.
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
        let parameter = ml_dsa::parameter_set(&object, ObjectClass::PUBLIC_KEY)?;
        let mechanism_type = request.input.mode().mechanism_type();
        let module = object.session.token().module.raw()?;
        if parameter != request.parameter_set
            || !ml_dsa::permission(&object, AttributeType::Verify)?
            || !ml_dsa::allowed_mechanism(&object, mechanism_type)?
            || !ml_dsa::mechanism_support(object.session.token(), parameter, mechanism_type, |i| {
                i.verify()
            })?
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
