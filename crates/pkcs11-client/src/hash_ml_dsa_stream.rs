// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Authentication, Client, Error, HashMlDsaCapabilities, ManagementSession, MlDsaParameterSet,
    MlDsaSigningOperation, MlDsaSigningPolicy, Pin, PrivateKeyRef, PublicKeyRef,
    input::read_chunks, ml_dsa::verification_error,
};
pub use pkcs11_runtime::{HashMlDsaParameters, HashMlDsaVerificationCapabilities};
use std::io::Read;

/// Exclusive token-hashed SHA-512 verifier. Chunks/contexts are not retained;
/// drop discards an incomplete session. Only completed mismatches permit reuse.
#[derive(Debug)]
pub struct HashMlDsaVerificationOperation<'a>(pkcs11_runtime::HashMlDsaVerificationOperation<'a>);
impl HashMlDsaVerificationOperation<'_> {
    /// Observed key parameter set, checked before initialization.
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.0.parameter_set()
    }
    /// Process one original-message chunk; failures prevent further native calls.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.0.update(bytes).map_err(verification_error)
    }
    /// Complete once. A malformed signature length discards the active session;
    /// reader helpers check that length before initialization instead.
    pub fn finish(self, signature: &[u8]) -> Result<(), Error> {
        self.0.finish(signature).map_err(verification_error)
    }
    /// Cancel once; unavailable/failed cancellation leaves the session unusable.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel().map_err(verification_error)
    }
}
impl ManagementSession<'_> {
    /// Inspect token-hashed SHA-512 signing streams independently of C_Sign.
    pub fn hash_ml_dsa_streaming_capabilities(
        &mut self,
        key: &PrivateKeyRef,
    ) -> Result<HashMlDsaCapabilities, Error> {
        Ok(self.session.hash_ml_dsa_streaming_capabilities(key)?)
    }
    /// Inspect public-key permissions and single/multipart verification pointers.
    pub fn hash_ml_dsa_verification_capabilities(
        &mut self,
        key: &PublicKeyRef,
    ) -> Result<HashMlDsaVerificationCapabilities, Error> {
        Ok(self.session.hash_ml_dsa_verification_capabilities(key)?)
    }
    /// Begin exclusive token-hashed SHA-512 signing. Context/PIN borrows end
    /// after initialization; input budgets and checked closure remain caller-owned.
    ///
    /// ```compile_fail,E0499
    /// use pkcs11_client::{Error, ManagementSession, HashMlDsaParameters, MlDsaSigningPolicy, PrivateKeyRef};
    /// fn overlap(session: &mut ManagementSession<'_>, key: &PrivateKeyRef, parameters: HashMlDsaParameters<'_>) -> Result<(), Error> {
    ///     let mut operation = session.start_hash_ml_dsa_signing(key, parameters, &MlDsaSigningPolicy::default(), None)?;
    ///     session.start_hash_ml_dsa_signing(key, parameters, &MlDsaSigningPolicy::default(), None)?;
    ///     operation.update(b"message")?;
    ///     Ok(())
    /// }
    /// ```
    pub fn start_hash_ml_dsa_signing(
        &mut self,
        key: &PrivateKeyRef,
        parameters: HashMlDsaParameters<'_>,
        policy: &MlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<MlDsaSigningOperation<'_>, Error> {
        Ok(MlDsaSigningOperation(
            self.session
                .start_hash_ml_dsa_signing(key, parameters, policy, context_pin)?,
        ))
    }
    /// Begin exclusive token-hashed SHA-512 verification through C_VerifyUpdate/Final.
    /// Context borrows end here. This does not establish certificate trust.
    pub fn start_hash_ml_dsa_verification(
        &mut self,
        key: &PublicKeyRef,
        parameters: HashMlDsaParameters<'_>,
    ) -> Result<HashMlDsaVerificationOperation<'_>, Error> {
        self.session
            .start_hash_ml_dsa_verification(key, parameters)
            .map(HashMlDsaVerificationOperation)
            .map_err(verification_error)
    }
    /// Sign original-message chunks with a zeroizing 64 KiB reader buffer. Empty
    /// input and Interrupted reads are supported. Read/native/unwind failures
    /// discard the active session. Callers enforce total budgets and check closure.
    pub fn sign_hash_ml_dsa_reader(
        &mut self,
        key: &PrivateKeyRef,
        parameters: HashMlDsaParameters<'_>,
        policy: &MlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
        reader: &mut impl Read,
    ) -> Result<Vec<u8>, Error> {
        let mut operation = self.start_hash_ml_dsa_signing(key, parameters, policy, context_pin)?;
        read_chunks(
            reader,
            |bytes| operation.update(bytes),
            Error::SignatureInput,
        )?;
        operation.finish()
    }
    /// Verify original-message chunks with a zeroizing 64 KiB buffer. Parameters
    /// and signature length are checked before initialization. Callers enforce
    /// total budgets; read/native/unwind failures discard incomplete sessions.
    pub fn verify_hash_ml_dsa_reader(
        &mut self,
        key: &PublicKeyRef,
        parameters: HashMlDsaParameters<'_>,
        signature: &[u8],
        reader: &mut impl Read,
    ) -> Result<(), Error> {
        parameters.request(&[]).validate()?;
        if signature.len() != parameters.parameter_set.signature_length() {
            return Err(Error::SignatureMismatch);
        }
        let mut operation = self.start_hash_ml_dsa_verification(key, parameters)?;
        read_chunks(
            reader,
            |bytes| operation.update(bytes),
            Error::SignatureInput,
        )?;
        operation.finish(signature)
    }
}
impl Client<'_> {
    /// Discover current token-hashed SHA-512 multipart signing support.
    pub fn hash_ml_dsa_streaming_capabilities(
        &self,
        key: &PrivateKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<HashMlDsaCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .hash_ml_dsa_streaming_capabilities(key)?)
    }
    /// Discover token-hashed SHA-512 public-key verification support.
    pub fn hash_ml_dsa_verification_capabilities(
        &self,
        key: &PublicKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<HashMlDsaVerificationCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .hash_ml_dsa_verification_capabilities(key)?)
    }
    /// Sign a reader while holding one exclusive pool lease. Policy precedes
    /// authentication. Uses a zeroizing 64 KiB buffer, with no software hashing,
    /// digest substitution or retry. Callers enforce budgets and check closure.
    pub fn sign_hash_ml_dsa_reader(
        &self,
        key: &PrivateKeyRef,
        parameters: HashMlDsaParameters<'_>,
        policy: &MlDsaSigningPolicy,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
        reader: &mut impl Read,
    ) -> Result<Vec<u8>, Error> {
        policy.validate_hash_ml_dsa(&parameters.request(&[]))?;
        let mut lease = self.pool().try_acquire(authentication)?;
        let mut operation =
            lease
                .session()
                .start_hash_ml_dsa_signing(key, parameters, policy, context_pin)?;
        read_chunks(
            reader,
            |bytes| Ok(operation.update(bytes)?),
            Error::SignatureInput,
        )?;
        Ok(operation.finish()?)
    }
    /// Verify a reader under an exclusive pool lease. Context/signature bounds
    /// precede checkout. Completed mismatches permit reuse; initialized read,
    /// native and unwind failures discard the session. Callers enforce budgets.
    pub fn verify_hash_ml_dsa_reader(
        &self,
        key: &PublicKeyRef,
        parameters: HashMlDsaParameters<'_>,
        signature: &[u8],
        authentication: Authentication<'_>,
        reader: &mut impl Read,
    ) -> Result<(), Error> {
        parameters.request(&[]).validate()?;
        if signature.len() != parameters.parameter_set.signature_length() {
            return Err(Error::SignatureMismatch);
        }
        let mut lease = self.pool().try_acquire(authentication)?;
        let mut operation = lease
            .session()
            .start_hash_ml_dsa_verification(key, parameters)
            .map_err(verification_error)?;
        read_chunks(
            reader,
            |bytes| operation.update(bytes).map_err(verification_error),
            Error::SignatureInput,
        )?;
        operation.finish(signature).map_err(verification_error)
    }
}
