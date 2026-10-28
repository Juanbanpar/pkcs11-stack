// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Authentication, Client, Error, Identity, ManagementSession, Pin, PrivateKeyRef, PublicKeyRef,
    SignInput, SignPlan, SignatureParameters, SigningChoice, SigningOptions, SigningPolicy,
    input::read_chunks,
};
use std::io::Read;

impl Client<'_> {
    /// Plan RSA/ECDSA message streaming under this client's policy and live
    /// multipart/raw entry points. Advisory only; execution rechecks capabilities.
    pub fn streaming_plan(
        &self,
        key: &PrivateKeyRef,
        parameters: SignatureParameters,
        authentication: Authentication<'_>,
    ) -> Result<SignPlan, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .streaming_key_capabilities(key)?
            .plan(&parameters.request(SignInput::Message(&[])), self.policy())?)
    }
    /// Sign an original RSA/ECDSA message using an exclusive pool lease and a
    /// zeroizing 64 KiB reader buffer. Hashing follows this client's policy; context
    /// authentication follows init. No binding is performed. Callers enforce input
    /// budgets and check close before releasing output. Read/native/unwind failures
    /// discard the lease; no fallback or retry occurs after initialization.
    pub fn sign_reader(
        &self,
        key: &PrivateKeyRef,
        parameters: SignatureParameters,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
        reader: &mut impl Read,
    ) -> Result<Vec<u8>, Error> {
        let mut lease = self.pool().try_acquire(authentication)?;
        let mut operation =
            lease
                .session()
                .start_signing(key, parameters, self.policy(), context_pin)?;
        read_chunks(
            reader,
            |bytes| Ok(operation.update(bytes)?),
            Error::SignatureInput,
        )?;
        Ok(operation.finish()?)
    }
    /// Verify an original RSA/ECDSA message with a selected token public key and
    /// an exclusive pool lease. Hashing follows this client's policy. A zeroizing
    /// 64 KiB buffer supports empty input and Interrupted reads; callers enforce
    /// budgets. Completed mismatches permit reuse, while read/native/unwind errors
    /// discard the initialized lease. Check close before publishing success.
    pub fn verify_token_reader(
        &self,
        key: &PublicKeyRef,
        parameters: SignatureParameters,
        authentication: Authentication<'_>,
        reader: &mut impl Read,
        signature: &[u8],
    ) -> Result<(), Error> {
        let mut lease = self.pool().try_acquire(authentication)?;
        let mut operation = lease
            .session()
            .start_verification(key, parameters, self.policy())?;
        read_chunks(
            reader,
            |bytes| Ok(operation.update(bytes)?),
            Error::SignatureInput,
        )?;
        match operation.finish(signature) {
            Err(pkcs11_runtime::Error::SignatureMismatch) => Err(Error::SignatureMismatch),
            result => Ok(result?),
        }
    }
    /// Sign a reader and verify the result against the bound certificate before
    /// release, detecting replacement keys under the same selector. Certificate
    /// parameters are validated before checkout or input. Incremental software
    /// hashing for this association check does not change the token/software
    /// signing policy. The message is read once through a zeroizing 64 KiB buffer;
    /// no full-message buffer, seek or retry is used. Input budgets and checked
    /// closure remain caller-owned. Read/native/unwind or association failures
    /// discard the lease; certificate trust remains application-owned.
    pub fn sign_identity_reader(
        &self,
        identity: &Identity,
        parameters: SignatureParameters,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
        reader: &mut impl Read,
    ) -> Result<Vec<u8>, Error> {
        identity
            .certificate()
            .validate_signing_request(&parameters.request(SignInput::Message(&[])))?;
        let mut lease = self.pool().try_acquire(authentication)?;
        let mut operation = lease.session().start_signing(
            identity.key(),
            parameters,
            self.policy(),
            context_pin,
        )?;
        let mut hash = crate::certificate::message_hasher(parameters.digest);
        read_chunks(
            reader,
            |bytes| {
                hash.update(bytes);
                Ok(operation.update(bytes)?)
            },
            Error::SignatureInput,
        )?;
        let signature = operation.finish()?;
        if let Err(error) = identity.certificate().verify(
            &parameters.request(SignInput::Digest(&hash.finalize())),
            &signature,
        ) {
            lease.discard();
            return Err(error);
        }
        Ok(signature)
    }
}

/// Exclusive RSA/ECDSA message signer. Hashing follows the selected policy.
/// Dropping before completion or confirmed cancellation discards the session.
#[derive(Debug)]
pub struct SigningOperation<'a>(pkcs11_runtime::SigningOperation<'a>);
/// Exclusive native RSA/ECDSA message verifier with independent public-key
/// permissions. Dropping before completion/cancellation discards the session.
#[derive(Debug)]
pub struct VerificationOperation<'a>(pkcs11_runtime::VerificationOperation<'a>);
impl SigningOperation<'_> {
    /// Inspect the selected mechanism, hashing boundary and context requirement.
    pub fn plan(&self) -> &SignPlan {
        self.0.plan()
    }
    /// Process a chunk, including empty input. Native failures prevent further use.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        Ok(self.0.update(bytes)?)
    }
    /// Finish once into at most 1024 bytes. Check closure before releasing output.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        Ok(self.0.finish()?)
    }
    /// Cancel once; only confirmed native termination restores session reuse.
    pub fn cancel(self) -> Result<(), Error> {
        Ok(self.0.cancel()?)
    }
}
impl VerificationOperation<'_> {
    /// Inspect the selected mechanism and hashing boundary.
    pub fn plan(&self) -> &SignPlan {
        self.0.plan()
    }
    /// Process a chunk, including empty input. Native failures prevent further use.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        Ok(self.0.update(bytes)?)
    }
    /// Complete native verification once, without DER conversion. Completed
    /// mismatches permit reuse; all other native failures require session closure.
    pub fn finish(self, signature: &[u8]) -> Result<(), Error> {
        match self.0.finish(signature) {
            Err(pkcs11_runtime::Error::SignatureMismatch) => Err(Error::SignatureMismatch),
            result => Ok(result?),
        }
    }
    /// Cancel once; only confirmed native termination restores session reuse.
    pub fn cancel(self) -> Result<(), Error> {
        Ok(self.0.cancel()?)
    }
}
impl ManagementSession<'_> {
    /// Advisory RSA/ECDSA streaming choices under the policy, checking actual
    /// multipart pointers for token hashing and raw completion for software hashing.
    pub fn streaming_signing_options(
        &mut self,
        key: &PrivateKeyRef,
        policy: &SigningPolicy,
    ) -> Result<SigningOptions, Error> {
        Ok(crate::signature_options::options(
            &self.session.streaming_key_capabilities(key)?,
            policy,
        ))
    }
    /// Advisory streaming verification choices using independent verification
    /// permissions, mechanism flags and native entry points.
    pub fn streaming_verification_options(
        &mut self,
        key: &PublicKeyRef,
        policy: &SigningPolicy,
    ) -> Result<Vec<SigningChoice>, Error> {
        Ok(crate::signature_options::verification_options(
            &self.session.streaming_verification_capabilities(key)?,
            policy,
        ))
    }
    /// Start exclusive RSA/ECDSA message signing. Context authentication occurs
    /// after init and before updates; the PIN is not retained. Hashing policy is
    /// resolved before initialization, with no fallback or retry afterward.
    /// Callers enforce their input budget. Drop discards incomplete sessions.
    ///
    /// ```compile_fail,E0499
    /// use pkcs11_client::{Error, ManagementSession, PrivateKeyRef, SignatureParameters, SigningPolicy};
    /// fn overlap(session: &mut ManagementSession<'_>, key: &PrivateKeyRef, parameters: SignatureParameters) -> Result<(), Error> {
    ///     let policy = SigningPolicy::default();
    ///     let mut operation = session.start_signing(key, parameters, &policy, None)?;
    ///     session.start_signing(key, parameters, &policy, None)?;
    ///     operation.update(b"message")?;
    ///     Ok(())
    /// }
    /// ```
    pub fn start_signing(
        &mut self,
        key: &PrivateKeyRef,
        parameters: SignatureParameters,
        policy: &SigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<SigningOperation<'_>, Error> {
        Ok(SigningOperation(self.session.start_signing(
            key,
            parameters,
            policy,
            context_pin,
        )?))
    }
    /// Start exclusive native RSA/ECDSA message verification. Hashing policy is
    /// resolved before init. Callers enforce their input budget; drop discards
    /// incomplete sessions. No certificate is needed and no trust is inferred.
    pub fn start_verification(
        &mut self,
        key: &PublicKeyRef,
        parameters: SignatureParameters,
        policy: &SigningPolicy,
    ) -> Result<VerificationOperation<'_>, Error> {
        Ok(VerificationOperation(
            self.session.start_verification(key, parameters, policy)?,
        ))
    }
    /// Sign a reader using a zeroizing 64 KiB input buffer and policy-selected
    /// token or incremental software hashing. Empty input and Interrupted reads
    /// are supported. Callers enforce their total input budget. Read/native failure
    /// discards the initialized session. No fallback or retry after init occurs.
    /// RSA output is modulus-width; ECDSA uses fixed-width r || s. Check closure
    /// before releasing output. This API does not perform certificate binding.
    pub fn sign_reader(
        &mut self,
        key: &PrivateKeyRef,
        parameters: SignatureParameters,
        policy: &SigningPolicy,
        context_pin: Option<Pin<'_>>,
        reader: &mut impl Read,
    ) -> Result<Vec<u8>, Error> {
        let mut operation = self.start_signing(key, parameters, policy, context_pin)?;
        read_chunks(
            reader,
            |bytes| operation.update(bytes),
            Error::SignatureInput,
        )?;
        operation.finish()
    }
    /// Verify a reader natively using a zeroizing 64 KiB buffer and explicit
    /// hashing policy. Empty input and Interrupted reads are supported; callers
    /// enforce their input budget. Completed mismatches permit reuse; read/native
    /// failures discard the initialized session. No certificate-trust claim is made.
    pub fn verify_token_reader(
        &mut self,
        key: &PublicKeyRef,
        parameters: SignatureParameters,
        policy: &SigningPolicy,
        reader: &mut impl Read,
        signature: &[u8],
    ) -> Result<(), Error> {
        let mut operation = self.start_verification(key, parameters, policy)?;
        read_chunks(
            reader,
            |bytes| operation.update(bytes),
            Error::SignatureInput,
        )?;
        operation.finish(signature)
    }
}
