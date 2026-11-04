// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    CancelFlags, Error, Function, MlDsaCapabilities, MlDsaHedging, MlDsaParameterSet, MlDsaRequest,
    MlDsaSigningPolicy, Pin, PrivateKeyRef, Session, error::backend,
};
use cryptoki::session::UserType;
use std::cell::Cell;

/// Pure ML-DSA parameters without message input. No prehash or external-mu mode.
/// Debug omits context bytes; native initialization consumes them synchronously.
#[derive(Clone, Copy)]
pub struct MlDsaParameters<'a> {
    /// Expected key parameter set; checked again before initialization.
    pub parameter_set: MlDsaParameterSet,
    /// Domain-separation context, at most 255 bytes. Empty means no context.
    pub context: &'a [u8],
    /// Explicit randomness requirement; no fallback after initialization.
    pub hedging: MlDsaHedging,
}
impl std::fmt::Debug for MlDsaParameters<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaParameters")
            .field("parameter_set", &self.parameter_set)
            .field("hedging", &self.hedging)
            .finish_non_exhaustive()
    }
}
impl<'a> MlDsaParameters<'a> {
    /// Borrow an original message for the existing single-part APIs or validation.
    pub fn request(&self, message: &'a [u8]) -> MlDsaRequest<'a> {
        MlDsaRequest {
            parameter_set: self.parameter_set,
            context: self.context,
            hedging: self.hedging,
            message,
        }
    }
}
/// Exclusively borrowed ML-DSA family signer. The initialization method selects
/// pure ML-DSA or token-hashed SHA-2/SHA-3 HashML-DSA. Message chunks, contexts and PINs are
/// not retained by the guard. Drop before successful finish or confirmed explicit
/// cancellation discards the session. Provider buffering/resource limits may apply.
pub struct MlDsaSigningOperation<'a> {
    raw: &'a cryptoki::session::Session,
    healthy: &'a Cell<bool>,
    parameter_set: MlDsaParameterSet,
    active: bool,
    updated: bool,
    cancellation_supported: bool,
}
impl std::fmt::Debug for MlDsaSigningOperation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaSigningOperation")
            .field("parameter_set", &self.parameter_set)
            .finish_non_exhaustive()
    }
}
impl Drop for MlDsaSigningOperation<'_> {
    fn drop(&mut self) {
        if self.active {
            self.healthy.set(false);
        }
    }
}
impl MlDsaSigningOperation<'_> {
    /// Observed key parameter set, checked against the request before init.
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }
    /// Process one original-message chunk, including empty input. No external
    /// hashing or total message limit is imposed; callers enforce their budget.
    /// Native failure prevents further updates, finalization and cancellation.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        if let Err(error) = self.raw.sign_update(bytes) {
            self.active = false;
            return Err(backend("update ML-DSA signature", error));
        }
        self.updated = true;
        Ok(())
    }
    /// Complete once into exactly 2420, 3309 or 4627 bytes, without output-size
    /// queries, retries or software fallback. Native failure and malformed output
    /// discard the session. An untouched stream sends an empty update before
    /// finalization. Check closure before publishing the signature.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        if !self.updated {
            self.update(&[])?;
        }
        let mut signature = vec![0; self.parameter_set.signature_length()];
        let written = self
            .raw
            .sign_final_into(&mut signature)
            .map_err(|e| backend("finish ML-DSA signature", e))?;
        if written != signature.len() {
            return Err(Error::InvalidSignature);
        }
        self.active = false;
        self.healthy.set(true);
        Ok(signature)
    }
    /// Cancel once. Only confirmed native termination restores session reuse;
    /// unsupported/failed cancellation requires closure. Drop never cancels.
    pub fn cancel(mut self) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        crate::cancellation::cancel(self.raw, self.cancellation_supported, CancelFlags::SIGN)?;
        self.active = false;
        self.healthy.set(true);
        Ok(())
    }
}
impl<'a> MlDsaSigningOperation<'a> {
    pub(crate) fn initialized(
        raw: &'a cryptoki::session::Session,
        healthy: &'a Cell<bool>,
        parameter_set: MlDsaParameterSet,
        cancellation_supported: bool,
    ) -> Self {
        Self {
            raw,
            healthy,
            parameter_set,
            active: true,
            updated: false,
            cancellation_supported,
        }
    }
}
fn capabilities(object: &crate::Object<'_, '_>) -> Result<MlDsaCapabilities, Error> {
    let mut caps = crate::ml_dsa::capabilities(object)?;
    let module = object.session.token().module.raw()?;
    caps.can_sign &= [
        Function::SignInit,
        Function::SignUpdate,
        Function::SignFinal,
    ]
    .into_iter()
    .all(|f| module.is_fn_supported(f))
        && (!caps.always_authenticate || module.is_fn_supported(Function::Login));
    Ok(caps)
}
impl Session<'_> {
    /// Advisory ML-DSA signing-stream capabilities with init/update/final entry
    /// points and context-login availability. No C_Sign pointer is required.
    pub fn ml_dsa_streaming_capabilities(
        &mut self,
        key: &PrivateKeyRef,
    ) -> Result<MlDsaCapabilities, Error> {
        capabilities(&self.resolve(key.as_object_ref())?)
    }
    /// Begin exclusive pure ML-DSA message signing with explicit context, hedging
    /// and policy. Context authentication follows init and precedes updates. PIN
    /// and context borrows end after this call. Input has no total bound; callers
    /// enforce their budget. Read/update/drop failures discard incomplete sessions.
    ///
    /// Streaming verification of ML-DSA requires the signature-first 3.2 API;
    /// C_VerifyUpdate/C_VerifyFinal are not permitted for this mechanism.
    pub fn start_ml_dsa_signing(
        &mut self,
        key: &PrivateKeyRef,
        parameters: MlDsaParameters<'_>,
        policy: &MlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<MlDsaSigningOperation<'_>, Error> {
        let request = parameters.request(&[]);
        policy.validate(&request)?;
        let object = self.resolve(key.as_object_ref())?;
        let caps = capabilities(&object)?;
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
        let mechanism = request.mechanism();
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        raw.sign_init(&mechanism, object.handle)
            .map_err(|e| backend("initialize ML-DSA signature stream", e))?;
        if caps.always_authenticate {
            raw.login(UserType::ContextSpecific, pin)
                .map_err(|e| backend("ML-DSA context login", e))?;
        }
        Ok(MlDsaSigningOperation {
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
