// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Error, ManagementSession, MlDsaCapabilities, MlDsaParameterSet, MlDsaParameters,
    MlDsaSigningPolicy, Pin, PrivateKeyRef, input::read_chunks,
};
use std::io::Read;

/// Exclusive pure ML-DSA signing stream. Contexts, PINs and message chunks are
/// not retained. Drop discards an unfinished session; no fallback or retry occurs.
#[derive(Debug)]
pub struct MlDsaSigningOperation<'a>(pkcs11_runtime::MlDsaSigningOperation<'a>);
impl MlDsaSigningOperation<'_> {
    /// Observed key parameter set, checked before initialization.
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.0.parameter_set()
    }
    /// Process an original-message chunk. Native failure prevents further use.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        Ok(self.0.update(bytes)?)
    }
    /// Complete once with fixed signature storage. Check closure before publishing.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        Ok(self.0.finish()?)
    }
    /// Cancel once; only confirmed native termination restores session reuse.
    pub fn cancel(self) -> Result<(), Error> {
        Ok(self.0.cancel()?)
    }
}
impl ManagementSession<'_> {
    /// Advisory signing-stream capabilities with multipart pointer and login gates.
    pub fn ml_dsa_streaming_capabilities(
        &mut self,
        key: &PrivateKeyRef,
    ) -> Result<MlDsaCapabilities, Error> {
        Ok(self.session.ml_dsa_streaming_capabilities(key)?)
    }
    /// Begin exclusive pure ML-DSA signing. Context login follows init; context and
    /// PIN borrows end after this call. Input has no total limit; callers enforce
    /// their budget. Abandonment/native failure discards the initialized session.
    ///
    /// ```compile_fail,E0499
    /// use pkcs11_client::{Error, ManagementSession, MlDsaParameters, MlDsaSigningPolicy, PrivateKeyRef};
    /// fn overlap(session: &mut ManagementSession<'_>, key: &PrivateKeyRef, parameters: MlDsaParameters<'_>) -> Result<(), Error> {
    ///     let policy = MlDsaSigningPolicy::default();
    ///     let mut operation = session.start_ml_dsa_signing(key, parameters, &policy, None)?;
    ///     session.start_ml_dsa_signing(key, parameters, &policy, None)?;
    ///     operation.update(b"message")?;
    ///     Ok(())
    /// }
    /// ```
    pub fn start_ml_dsa_signing(
        &mut self,
        key: &PrivateKeyRef,
        parameters: MlDsaParameters<'_>,
        policy: &MlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<MlDsaSigningOperation<'_>, Error> {
        Ok(MlDsaSigningOperation(self.session.start_ml_dsa_signing(
            key,
            parameters,
            policy,
            context_pin,
        )?))
    }
    /// Sign a reader using pure ML-DSA with a zeroizing 64 KiB input buffer. Empty
    /// input and Interrupted reads are supported. No prehash, whole-input buffering
    /// or total input limit is imposed; callers enforce their budget and the token
    /// may impose its own resource limits. Read/native failures discard the session.
    /// Output is exactly the selected parameter set's signature length. Check closure
    /// before publishing. This management API does not perform certificate binding.
    pub fn sign_ml_dsa_reader(
        &mut self,
        key: &PrivateKeyRef,
        parameters: MlDsaParameters<'_>,
        policy: &MlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
        reader: &mut impl Read,
    ) -> Result<Vec<u8>, Error> {
        let mut operation = self.start_ml_dsa_signing(key, parameters, policy, context_pin)?;
        read_chunks(
            reader,
            |bytes| operation.update(bytes),
            Error::SignatureInput,
        )?;
        operation.finish()
    }
}
