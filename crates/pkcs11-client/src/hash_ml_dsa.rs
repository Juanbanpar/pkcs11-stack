// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Authentication, Client, Error, ManagementSession, MlDsaSigningPolicy, Pin, PrivateKeyRef,
    PublicKeyRef,
};
pub use pkcs11_runtime::{HashMlDsaCapabilities, HashMlDsaInput, HashMlDsaMode, HashMlDsaRequest};

fn verification_error(error: pkcs11_runtime::Error) -> Error {
    match error {
        pkcs11_runtime::Error::SignatureMismatch => Error::SignatureMismatch,
        other => other.into(),
    }
}
impl ManagementSession<'_> {
    /// Advisory support for one HashML-DSA hash/input mode and private key.
    pub fn hash_ml_dsa_capabilities(
        &mut self,
        key: &PrivateKeyRef,
        mode: HashMlDsaMode,
    ) -> Result<HashMlDsaCapabilities, Error> {
        Ok(self.session.hash_ml_dsa_capabilities(key, mode)?)
    }
    /// Sign once using explicit original-message or exact-length digest input.
    /// Close the session before releasing output when checked cleanup is required.
    pub fn sign_hash_ml_dsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &HashMlDsaRequest<'_>,
        policy: &MlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .session
            .sign_hash_ml_dsa(key, request, policy, context_pin)?)
    }
    /// Verify on the token; does not bind a private key or establish certificate trust.
    pub fn verify_hash_ml_dsa(
        &mut self,
        key: &PublicKeyRef,
        request: &HashMlDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.session
            .verify_hash_ml_dsa(key, request, signature)
            .map_err(verification_error)
    }
}
impl Client<'_> {
    /// Discover current permissions and native support for one HashML-DSA mode.
    pub fn hash_ml_dsa_capabilities(
        &self,
        key: &PrivateKeyRef,
        mode: HashMlDsaMode,
        authentication: Authentication<'_>,
    ) -> Result<HashMlDsaCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .hash_ml_dsa_capabilities(key, mode)?)
    }
    /// Sign once without external hashing, software fallback or cached key handles.
    /// Input, context and PIN are borrowed only for this call.
    pub fn sign_hash_ml_dsa(
        &self,
        key: &PrivateKeyRef,
        request: &HashMlDsaRequest<'_>,
        policy: &MlDsaSigningPolicy,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        policy.validate_hash_ml_dsa(request)?;
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .sign_hash_ml_dsa(key, request, policy, context_pin)?)
    }
    /// Verify with a uniquely selected token public key. Completed mismatches
    /// permit session reuse; other provider failures discard the pooled session.
    pub fn verify_hash_ml_dsa(
        &self,
        key: &PublicKeyRef,
        request: &HashMlDsaRequest<'_>,
        signature: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        request.validate()?;
        if signature.len() != request.parameter_set.signature_length() {
            return Err(Error::SignatureMismatch);
        }
        self.pool()
            .try_acquire(authentication)?
            .session()
            .verify_hash_ml_dsa(key, request, signature)
            .map_err(verification_error)
    }
}
