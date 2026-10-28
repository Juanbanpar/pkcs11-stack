// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Error, Function, InterfaceVersion, MlDsaParameterSet, MlDsaParameters, MlDsaRequest, Object,
    PublicKeyRef, Session, error::backend,
};
use cryptoki::error::{Error as NativeError, RvError};
use std::cell::Cell;

/// Advisory public-key permissions and selected 3.2 signature-first entry points.
/// Existing C_Verify support is independent of these capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlDsaVerificationCapabilities {
    /// Observed public-key parameter set.
    pub parameter_set: MlDsaParameterSet,
    /// Signature-first single-part init/completion are available and permitted.
    pub can_verify: bool,
    /// Signature-first init/update/final are available and permitted.
    pub can_stream: bool,
}
fn capabilities(object: &Object<'_, '_>) -> Result<MlDsaVerificationCapabilities, Error> {
    let (parameter_set, permitted) = crate::ml_dsa::verification_key(object)?;
    let module = &object.session.token().module;
    let permitted = permitted
        && module.interface().version == InterfaceVersion::V3_2
        && module.supports_function(Function::VerifySignatureInit);
    Ok(MlDsaVerificationCapabilities {
        parameter_set,
        can_verify: permitted && module.supports_function(Function::VerifySignature),
        can_stream: permitted
            && module.supports_function(Function::VerifySignatureUpdate)
            && module.supports_function(Function::VerifySignatureFinal),
    })
}

/// Exclusive pure ML-DSA verifier using PKCS#11 3.2's signature-first API.
/// Signature/context bytes are consumed by native initialization and not retained
/// by this guard. Drop discards incomplete sessions; no implicit cancellation.
pub struct MlDsaVerificationOperation<'a> {
    raw: &'a cryptoki::session::Session,
    healthy: &'a Cell<bool>,
    parameter_set: MlDsaParameterSet,
    active: bool,
    updated: bool,
}
impl std::fmt::Debug for MlDsaVerificationOperation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaVerificationOperation")
            .field("parameter_set", &self.parameter_set)
            .finish_non_exhaustive()
    }
}
impl Drop for MlDsaVerificationOperation<'_> {
    fn drop(&mut self) {
        if self.active {
            self.healthy.set(false);
        }
    }
}
impl MlDsaVerificationOperation<'_> {
    /// Observed public-key parameter set, checked before initialization.
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }
    /// Process an original-message chunk, including empty input. Native failure
    /// prevents further use, including cancellation; callers enforce input budgets.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        if let Err(error) = self.raw.verify_signature_update(bytes) {
            self.active = false;
            return Err(backend("update ML-DSA signature-first verification", error));
        }
        self.updated = true;
        Ok(())
    }
    fn complete(&mut self, result: Result<(), NativeError>) -> Result<(), Error> {
        let result = match result {
            Ok(()) => Ok(()),
            Err(NativeError::Pkcs11(
                RvError::SignatureInvalid | RvError::SignatureLenRange,
                Function::VerifySignature | Function::VerifySignatureFinal,
            )) => Err(Error::SignatureMismatch),
            Err(error) => {
                return Err(backend(
                    "complete ML-DSA signature-first verification",
                    error,
                ));
            }
        };
        self.active = false;
        self.healthy.set(true);
        result
    }
    /// Complete once. Only native success or a completed signature mismatch
    /// permits session reuse. An untouched stream sends an empty update before
    /// finalization. Other errors require closure; no fallback or retry.
    pub fn finish(mut self) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        if !self.updated {
            self.update(&[])?;
        }
        self.complete(self.raw.verify_signature_final())
    }
    /// Cancel once through C_VerifySignatureInit with a NULL mechanism. Only
    /// confirmed native termination restores reuse; failure requires closure.
    /// No generic session cancellation or fallback is attempted.
    pub fn cancel(mut self) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        self.raw
            .cancel_signature_verification()
            .map_err(|error| backend("cancel ML-DSA signature-first verification", error))?;
        self.active = false;
        self.healthy.set(true);
        Ok(())
    }
}
impl Session<'_> {
    /// Discover signature-first single-part and streaming verification support.
    /// Checks only public-key verification permissions and the selected 3.2 table.
    pub fn ml_dsa_verification_capabilities(
        &mut self,
        key: &PublicKeyRef,
    ) -> Result<MlDsaVerificationCapabilities, Error> {
        capabilities(&self.resolve(key.as_object_ref())?)
    }
    fn ml_dsa_verifier(
        &mut self,
        key: &PublicKeyRef,
        parameters: MlDsaParameters<'_>,
        signature: &[u8],
        stream: bool,
    ) -> Result<MlDsaVerificationOperation<'_>, Error> {
        let request = parameters.request(&[]);
        request.validate()?;
        if signature.len() != parameters.parameter_set.signature_length() {
            return Err(Error::SignatureMismatch);
        }
        let object = self.resolve(key.as_object_ref())?;
        let caps = capabilities(&object)?;
        if caps.parameter_set != parameters.parameter_set
            || !(if stream {
                caps.can_stream
            } else {
                caps.can_verify
            })
        {
            return Err(Error::UnsupportedSigning(
                "ML-DSA signature-first verification",
            ));
        }
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        raw.verify_signature_init(&request.mechanism(), object.handle, signature)
            .map_err(|error| backend("initialize ML-DSA signature-first verification", error))?;
        Ok(MlDsaVerificationOperation {
            raw,
            healthy: &object.session.healthy,
            parameter_set: caps.parameter_set,
            active: true,
            updated: false,
        })
    }
    /// Begin exclusive pure ML-DSA verification with the signature supplied first.
    /// Signature/context borrows end after this call; hedging is ignored for
    /// verification. Read/update/drop failures discard incomplete sessions.
    /// Requires 3.2 init/update/final pointers, with no older-API fallback. Does
    /// not establish certificate trust or a private-key association.
    pub fn start_ml_dsa_verification(
        &mut self,
        key: &PublicKeyRef,
        parameters: MlDsaParameters<'_>,
        signature: &[u8],
    ) -> Result<MlDsaVerificationOperation<'_>, Error> {
        self.ml_dsa_verifier(key, parameters, signature, true)
    }
    /// Verify one original message through C_VerifySignatureInit/C_VerifySignature.
    /// Explicitly requires signature-first support; the older verify_ml_dsa API
    /// remains available independently. Malformed signature lengths fail before
    /// native initialization. Only completed mismatches permit reuse after errors.
    pub fn verify_ml_dsa_signature_first(
        &mut self,
        key: &PublicKeyRef,
        request: &MlDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        let mut operation = self.ml_dsa_verifier(
            key,
            MlDsaParameters {
                parameter_set: request.parameter_set,
                context: request.context,
                hedging: request.hedging,
            },
            signature,
            false,
        )?;
        operation.complete(operation.raw.verify_signature(request.message))
    }
}
