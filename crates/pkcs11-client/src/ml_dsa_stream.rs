// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Authentication, Client, Error, ManagementSession, MlDsaCapabilities, MlDsaIdentity,
    MlDsaParameterSet, MlDsaParameters, MlDsaRequest, MlDsaSigningPolicy,
    MlDsaVerificationCapabilities, Pin, PrivateKeyRef, PublicKeyRef, input::read_chunks,
    ml_dsa::verification_error,
};
use std::io::Read;

impl Client<'_> {
    /// Advisory ML-DSA signing-stream capabilities, including native multipart
    /// pointers. Execution rediscoveries and policy validation remain authoritative.
    pub fn ml_dsa_streaming_capabilities(
        &self,
        key: &PrivateKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<MlDsaCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .ml_dsa_streaming_capabilities(key)?)
    }
    /// Sign an original pure ML-DSA message with an exclusive pool lease and a
    /// zeroizing 64 KiB reader buffer. Policy is checked before authentication;
    /// context authentication follows init. Callers enforce budgets and check
    /// closure before publication. Read/native/input-unwind failures discard the
    /// initialized lease. No prehash, software signing fallback or retry occurs.
    pub fn sign_ml_dsa_reader(
        &self,
        key: &PrivateKeyRef,
        parameters: MlDsaParameters<'_>,
        policy: &MlDsaSigningPolicy,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
        reader: &mut impl Read,
    ) -> Result<Vec<u8>, Error> {
        policy.validate(&parameters.request(&[]))?;
        let mut lease = self.pool().try_acquire(authentication)?;
        let mut operation =
            lease
                .session()
                .start_ml_dsa_signing(key, parameters, policy, context_pin)?;
        read_chunks(
            reader,
            |bytes| Ok(operation.update(bytes)?),
            Error::SignatureInput,
        )?;
        Ok(operation.finish()?)
    }
    /// Sign once and verify against the bound certificate before release. Original
    /// chunks go to the token; RustCrypto incrementally computes the pure FIPS 204
    /// message value for software verification of the same input/context. Reads
    /// once without seeking or whole-message buffering. Policy/certificate checks
    /// precede authentication; association failures discard the lease. Input budgets
    /// and checked closure remain caller-owned. No certificate trust is asserted.
    pub fn sign_ml_dsa_identity_reader(
        &self,
        identity: &MlDsaIdentity,
        parameters: MlDsaParameters<'_>,
        policy: &MlDsaSigningPolicy,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
        reader: &mut impl Read,
    ) -> Result<Vec<u8>, Error> {
        policy.validate(&parameters.request(&[]))?;
        identity
            .certificate()
            .validate_signing_request(&parameters.request(&[]))?;
        let mut lease = self.pool().try_acquire(authentication)?;
        let mut operation = lease.session().start_ml_dsa_signing(
            identity.key(),
            parameters,
            policy,
            context_pin,
        )?;
        let key = identity.certificate().verifying_key();
        let mu = key.read_mu(parameters, reader, |bytes| Ok(operation.update(bytes)?))?;
        let signature = operation.finish()?;
        if let Err(error) = key.verify_mu(&mu, &signature) {
            lease.discard();
            return Err(match error {
                Error::SignatureMismatch => Error::KeyCertificateMismatch,
                other => other,
            });
        }
        Ok(signature)
    }
    /// Verify an original pure ML-DSA reader using an exclusive pool lease and
    /// the selected 3.2 signature-first API. Context/signature validation precedes
    /// checkout. A zeroizing 64 KiB buffer supports empty input and Interrupted
    /// reads; callers enforce budgets and check closure. Completed mismatches
    /// permit reuse, other initialized failures discard. No older-API retry occurs.
    pub fn verify_ml_dsa_reader(
        &self,
        key: &PublicKeyRef,
        parameters: MlDsaParameters<'_>,
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
            .start_ml_dsa_verification(key, parameters, signature)
            .map_err(verification_error)?;
        read_chunks(
            reader,
            |bytes| operation.update(bytes).map_err(verification_error),
            Error::SignatureInput,
        )?;
        operation.finish().map_err(verification_error)
    }
}

/// Exclusive ML-DSA family signing stream, initialized as pure ML-DSA or
/// token-hashed SHA-2/SHA-3 HashML-DSA. Contexts, PINs and message chunks are
/// not retained. Drop discards an unfinished session; no fallback or retry occurs.
#[derive(Debug)]
pub struct MlDsaSigningOperation<'a>(pub(crate) pkcs11_runtime::MlDsaSigningOperation<'a>);
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

/// Exclusive pure ML-DSA signature-first verifier. Drop discards incomplete
/// sessions; no legacy verification fallback, prehash or retry occurs.
#[derive(Debug)]
pub struct MlDsaVerificationOperation<'a>(pkcs11_runtime::MlDsaVerificationOperation<'a>);
impl MlDsaVerificationOperation<'_> {
    /// Observed public-key parameter set, checked at initialization.
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.0.parameter_set()
    }
    /// Process an original-message chunk. Native failure prevents further use.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.0.update(bytes).map_err(verification_error)
    }
    /// Complete once. Completed mismatches return SignatureMismatch and permit reuse.
    pub fn finish(self) -> Result<(), Error> {
        self.0.finish().map_err(verification_error)
    }
    /// Cancel once; only confirmed native termination restores reuse.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel().map_err(verification_error)
    }
}
impl ManagementSession<'_> {
    /// Discover selected 3.2 signature-first single-part and streaming capabilities.
    pub fn ml_dsa_verification_capabilities(
        &mut self,
        key: &PublicKeyRef,
    ) -> Result<MlDsaVerificationCapabilities, Error> {
        Ok(self.session.ml_dsa_verification_capabilities(key)?)
    }
    /// Begin exclusive pure ML-DSA verification with a signature supplied first.
    /// Signature/context borrows end after this call. Requires the selected 3.2
    /// init/update/final pointers; no fallback to the older C_Verify API occurs.
    ///
    /// ```compile_fail,E0499
    /// use pkcs11_client::{Error, ManagementSession, MlDsaParameters, PublicKeyRef};
    /// fn overlap(session: &mut ManagementSession<'_>, key: &PublicKeyRef, parameters: MlDsaParameters<'_>, signature: &[u8]) -> Result<(), Error> {
    ///     let mut operation = session.start_ml_dsa_verification(key, parameters, signature)?;
    ///     session.start_ml_dsa_verification(key, parameters, signature)?;
    ///     operation.update(b"message")?;
    ///     Ok(())
    /// }
    /// ```
    pub fn start_ml_dsa_verification(
        &mut self,
        key: &PublicKeyRef,
        parameters: MlDsaParameters<'_>,
        signature: &[u8],
    ) -> Result<MlDsaVerificationOperation<'_>, Error> {
        self.session
            .start_ml_dsa_verification(key, parameters, signature)
            .map(MlDsaVerificationOperation)
            .map_err(verification_error)
    }
    /// Verify one original message through the explicit signature-first API.
    /// Existing single-part verify_ml_dsa remains independently available.
    pub fn verify_ml_dsa_signature_first(
        &mut self,
        key: &PublicKeyRef,
        request: &MlDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.session
            .verify_ml_dsa_signature_first(key, request, signature)
            .map_err(verification_error)
    }
    /// Verify a reader with the signature supplied before input. Uses a zeroizing
    /// 64 KiB buffer, supports empty input/Interrupted reads, and imposes no total
    /// limit. Callers enforce budgets; provider resource limits may apply. Read,
    /// update and abandonment failures discard the session; completed mismatches
    /// permit reuse. Does not establish certificate trust or private-key association.
    pub fn verify_ml_dsa_reader(
        &mut self,
        key: &PublicKeyRef,
        parameters: MlDsaParameters<'_>,
        signature: &[u8],
        reader: &mut impl Read,
    ) -> Result<(), Error> {
        let mut operation = self.start_ml_dsa_verification(key, parameters, signature)?;
        read_chunks(
            reader,
            |bytes| operation.update(bytes),
            Error::SignatureInput,
        )?;
        operation.finish()
    }
}
