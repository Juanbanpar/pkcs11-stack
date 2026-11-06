// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Authentication, Client, Error, ManagementSession, ObjectRef, Plaintext};
pub use pkcs11_runtime::{
    AES_CCM_MAXIMUM_AAD, AES_CCM_MAXIMUM_PLAINTEXT, AES_CCM_NONCE_LENGTH, AES_CCM_TAG_LENGTH,
    AesCcmCapabilities, AesCcmDecryptRequest, AesCcmEncryptRequest, AesCcmOperation,
};
impl ManagementSession<'_> {
    /// Advisory AES-CCM support after current class, size, permission, mechanism
    /// and native entry-point checks. Does not perform crypto or read key values.
    pub fn aes_ccm_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: AesCcmOperation,
    ) -> Result<AesCcmCapabilities, Error> {
        Ok(self.session.aes_ccm_capabilities(key, operation)?)
    }
    /// Encrypt once using the supplied 12-byte nonce, with a full 16-byte tag.
    /// Returns ciphertext || tag without an envelope. The caller must ensure nonce
    /// uniqueness per key across writers/restarts, including after errors. No nonce
    /// generation, retry or software fallback occurs. Check session closure.
    pub fn encrypt_aes_ccm(
        &mut self,
        key: &ObjectRef,
        request: &AesCcmEncryptRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.encrypt_aes_ccm(key, request)?)
    }
    /// Authenticate/decrypt once. Provider failures return no plaintext and
    /// invalidate the session; preflight rejection does not. Successful plaintext
    /// zeroizes on drop and has redacted Debug.
    /// Native output buffers zeroize on failure and on drop. No retry
    /// or multipart plaintext release occurs. Check closure before releasing output.
    pub fn decrypt_aes_ccm(
        &mut self,
        key: &ObjectRef,
        request: &AesCcmDecryptRequest<'_>,
    ) -> Result<Plaintext, Error> {
        Ok(self.session.decrypt_aes_ccm(key, request)?)
    }
}

impl Client<'_> {
    /// Check current native AES-CCM support without reading key values.
    pub fn aes_ccm_capabilities(
        &self,
        key: &ObjectRef,
        operation: AesCcmOperation,
        authentication: Authentication<'_>,
    ) -> Result<AesCcmCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .aes_ccm_capabilities(key, operation)?)
    }
    /// Encrypt once with caller-managed nonce uniqueness. Never retries or substitutes a mode.
    pub fn encrypt_aes_ccm(
        &self,
        key: &ObjectRef,
        request: &AesCcmEncryptRequest<'_>,
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        request.validate()?;
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .encrypt_aes_ccm(key, request)?)
    }
    /// Authenticate before returning zeroizing plaintext. Native failures discard the pooled session.
    pub fn decrypt_aes_ccm(
        &self,
        key: &ObjectRef,
        request: &AesCcmDecryptRequest<'_>,
        authentication: Authentication<'_>,
    ) -> Result<Plaintext, Error> {
        request.validate()?;
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .decrypt_aes_ccm(key, request)?)
    }
}
