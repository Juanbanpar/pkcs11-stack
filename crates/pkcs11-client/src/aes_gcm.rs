// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, ManagementSession, ObjectRef, Plaintext};
pub use pkcs11_runtime::{
    AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_PLAINTEXT, AES_GCM_NONCE_LENGTH, AES_GCM_TAG_LENGTH,
    AesGcmCapabilities, AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmOperation,
};
impl ManagementSession<'_> {
    /// Advisory AES-GCM support after current class, size, permission, mechanism
    /// and native entry-point checks. Does not perform crypto or read key values.
    pub fn aes_gcm_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: AesGcmOperation,
    ) -> Result<AesGcmCapabilities, Error> {
        Ok(self.session.aes_gcm_capabilities(key, operation)?)
    }
    /// Encrypt once using the supplied 12-byte nonce, with a full 16-byte tag.
    /// Returns ciphertext || tag without an envelope. The caller must ensure nonce
    /// uniqueness per key across writers/restarts, including after errors. No nonce
    /// generation, retry or software fallback occurs. Check session closure.
    pub fn encrypt_aes_gcm(
        &mut self,
        key: &ObjectRef,
        request: &AesGcmEncryptRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.encrypt_aes_gcm(key, request)?)
    }
    /// Authenticate/decrypt once. Provider failures return no plaintext and
    /// invalidate the session; preflight rejection does not. Successful plaintext
    /// zeroizes on drop and has redacted Debug.
    /// cryptoki's transient failed buffers cannot be guaranteed zeroized. No retry
    /// or multipart plaintext release occurs. Check closure before releasing output.
    pub fn decrypt_aes_gcm(
        &mut self,
        key: &ObjectRef,
        request: &AesGcmDecryptRequest<'_>,
    ) -> Result<Plaintext, Error> {
        Ok(self.session.decrypt_aes_gcm(key, request)?)
    }
}
