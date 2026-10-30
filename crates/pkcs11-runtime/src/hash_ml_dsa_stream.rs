// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    CancelFlags, Error, Function, HashMlDsaCapabilities, HashMlDsaInput, HashMlDsaMode,
    HashMlDsaRequest, MlDsaHedging, MlDsaParameterSet, MlDsaSigningOperation, MlDsaSigningPolicy,
    Pin, PrivateKeyRef, PublicKeyRef, Session, error::backend, hash_ml_dsa,
};
use cryptoki::{
    error::{Error as NativeError, RvError},
    session::UserType,
};
use std::cell::Cell;

/// Token-hashed SHA-512 HashML-DSA parameters without message input.
/// Context/PIN borrows end at initialization. Caller-computed digests are not accepted.
#[derive(Clone, Copy)]
pub struct HashMlDsaParameters<'a> {
    /// Expected key parameter set, rediscovered before initialization.
    pub parameter_set: MlDsaParameterSet,
    /// FIPS 204 context, at most 255 bytes.
    pub context: &'a [u8],
    /// Explicit signing randomness requirement; ignored during verification.
    pub hedging: MlDsaHedging,
}
impl std::fmt::Debug for HashMlDsaParameters<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashMlDsaParameters")
            .field("parameter_set", &self.parameter_set)
            .field("hedging", &self.hedging)
            .finish_non_exhaustive()
    }
}
impl<'a> HashMlDsaParameters<'a> {
    /// Borrow an original message for validation or the existing single-part API.
    pub fn request(self, message: &'a [u8]) -> HashMlDsaRequest<'a> {
        HashMlDsaRequest {
            parameter_set: self.parameter_set,
            input: HashMlDsaInput::Message(message),
            context: self.context,
            hedging: self.hedging,
        }
    }
}

/// Advisory token-hashed SHA-512 verification support, independent of signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashMlDsaVerificationCapabilities {
    /// Observed public-key parameter set.
    pub parameter_set: MlDsaParameterSet,
    /// Native init/single-part completion are present and permitted.
    pub can_verify: bool,
    /// Native init/update/final are present and permitted, without requiring C_Verify.
    pub can_stream: bool,
}
fn signing_capabilities(object: &crate::Object<'_, '_>) -> Result<HashMlDsaCapabilities, Error> {
    hash_ml_dsa::capabilities_with_functions(
        object,
        HashMlDsaMode::Message,
        &[
            Function::SignInit,
            Function::SignUpdate,
            Function::SignFinal,
        ],
    )
}
fn verification_capabilities(
    object: &crate::Object<'_, '_>,
) -> Result<HashMlDsaVerificationCapabilities, Error> {
    let (parameter_set, permitted) = hash_ml_dsa::verification_key(object, HashMlDsaMode::Message)?;
    let module = object.session.token().module.raw()?;
    let permitted = permitted && module.is_fn_supported(Function::VerifyInit);
    Ok(HashMlDsaVerificationCapabilities {
        parameter_set,
        can_verify: permitted && module.is_fn_supported(Function::Verify),
        can_stream: permitted
            && module.is_fn_supported(Function::VerifyUpdate)
            && module.is_fn_supported(Function::VerifyFinal),
    })
}

/// Exclusive token-hashed SHA-512 HashML-DSA verifier using C_VerifyUpdate/Final.
/// Drop before completion or confirmed cancellation discards the session. Message
/// chunks and contexts are not retained. Provider buffering/resource limits may apply.
pub struct HashMlDsaVerificationOperation<'a> {
    raw: &'a cryptoki::session::Session,
    healthy: &'a Cell<bool>,
    parameter_set: MlDsaParameterSet,
    active: bool,
    updated: bool,
    cancellation_supported: bool,
}
impl std::fmt::Debug for HashMlDsaVerificationOperation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashMlDsaVerificationOperation")
            .field("parameter_set", &self.parameter_set)
            .finish_non_exhaustive()
    }
}
impl Drop for HashMlDsaVerificationOperation<'_> {
    fn drop(&mut self) {
        if self.active {
            self.healthy.set(false);
        }
    }
}
impl HashMlDsaVerificationOperation<'_> {
    /// Observed public-key parameter set, checked before initialization.
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }
    /// Process one original-message chunk, including empty input. Native failure
    /// prevents further updates, finalization or cancellation. Callers enforce budgets.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        if let Err(error) = self.raw.verify_update(bytes) {
            self.active = false;
            return Err(backend("update HashML-DSA verification", error));
        }
        self.updated = true;
        Ok(())
    }
    /// Complete once. Only native success or a completed mismatch permits reuse.
    /// A malformed signature length discards the initialized session without a native
    /// completion. An untouched stream sends an empty update before finalization.
    pub fn finish(mut self, signature: &[u8]) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        if signature.len() != self.parameter_set.signature_length() {
            return Err(Error::SignatureMismatch);
        }
        if !self.updated {
            self.update(&[])?;
        }
        let result = match self.raw.verify_final(signature) {
            Ok(()) => Ok(()),
            Err(NativeError::Pkcs11(
                RvError::SignatureInvalid | RvError::SignatureLenRange,
                Function::VerifyFinal,
            )) => Err(Error::SignatureMismatch),
            Err(error) => return Err(backend("finish HashML-DSA verification", error)),
        };
        self.active = false;
        self.healthy.set(true);
        result
    }
    /// Cancel once with CKF_VERIFY. Only confirmed termination restores reuse;
    /// unavailable/failed cancellation requires closure. Drop never cancels.
    pub fn cancel(mut self) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        crate::cancellation::cancel(self.raw, self.cancellation_supported, CancelFlags::VERIFY)?;
        self.active = false;
        self.healthy.set(true);
        Ok(())
    }
}
impl Session<'_> {
    /// Discover token-hashed SHA-512 signing streams independently of C_Sign.
    pub fn hash_ml_dsa_streaming_capabilities(
        &mut self,
        key: &PrivateKeyRef,
    ) -> Result<HashMlDsaCapabilities, Error> {
        signing_capabilities(&self.resolve(key.as_object_ref())?)
    }
    /// Discover token-hashed SHA-512 public-key verification permissions and pointers.
    /// These C_Verify entry points are independent of the 3.2 signature-first API.
    pub fn hash_ml_dsa_verification_capabilities(
        &mut self,
        key: &PublicKeyRef,
    ) -> Result<HashMlDsaVerificationCapabilities, Error> {
        verification_capabilities(&self.resolve(key.as_object_ref())?)
    }
    /// Begin exclusive token-hashed SHA-512 signing. Context login follows init and
    /// precedes updates. Context/PIN borrows end here. Read/update/drop failures
    /// discard incomplete sessions. Input budgets and checked closure are caller-owned.
    pub fn start_hash_ml_dsa_signing(
        &mut self,
        key: &PrivateKeyRef,
        parameters: HashMlDsaParameters<'_>,
        policy: &MlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<MlDsaSigningOperation<'_>, Error> {
        let request = parameters.request(&[]);
        policy.validate_hash_ml_dsa(&request)?;
        let object = self.resolve(key.as_object_ref())?;
        let caps = signing_capabilities(&object)?;
        caps.validate(&request, policy)?;
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
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        raw.sign_init(&request.mechanism(), object.handle)
            .map_err(|e| backend("initialize HashML-DSA signature stream", e))?;
        if caps.always_authenticate {
            raw.login(UserType::ContextSpecific, pin)
                .map_err(|e| backend("HashML-DSA context login", e))?;
        }
        Ok(MlDsaSigningOperation::initialized(
            raw,
            &object.session.healthy,
            caps.parameter_set,
            object
                .session
                .token()
                .module
                .supports_function(Function::SessionCancel),
        ))
    }
    /// Begin exclusive token-hashed SHA-512 verification. No signature is supplied
    /// until finish. Context borrows end here; only completed mismatches permit reuse.
    /// Uses C_VerifyInit/Update/Final through any supported table, with no fallback.
    pub fn start_hash_ml_dsa_verification(
        &mut self,
        key: &PublicKeyRef,
        parameters: HashMlDsaParameters<'_>,
    ) -> Result<HashMlDsaVerificationOperation<'_>, Error> {
        let request = parameters.request(&[]);
        request.validate()?;
        let object = self.resolve(key.as_object_ref())?;
        let caps = verification_capabilities(&object)?;
        if caps.parameter_set != parameters.parameter_set || !caps.can_stream {
            return Err(Error::UnsupportedSigning("HashML-DSA verification stream"));
        }
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        raw.verify_init(&request.mechanism(), object.handle)
            .map_err(|e| backend("initialize HashML-DSA verification stream", e))?;
        Ok(HashMlDsaVerificationOperation {
            raw,
            healthy: &object.session.healthy,
            parameter_set: caps.parameter_set,
            active: true,
            updated: false,
            cancellation_supported: object
                .session
                .token()
                .module
                .supports_function(Function::SessionCancel),
        })
    }
}
