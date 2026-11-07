// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Authentication, Client, Error, ManagementSession, ObjectRef, Plaintext};
pub use pkcs11_runtime::{
    CHACHA20_POLY1305_MAXIMUM_AAD, CHACHA20_POLY1305_MAXIMUM_PLAINTEXT,
    CHACHA20_POLY1305_NONCE_LENGTH, CHACHA20_POLY1305_TAG_LENGTH, ChaCha20Poly1305Capabilities,
    ChaCha20Poly1305DecryptRequest, ChaCha20Poly1305EncryptRequest, ChaCha20Poly1305KeyRequest,
    ChaCha20Poly1305Operation,
};
impl ManagementSession<'_> {
    /// Advisory ChaCha20-Poly1305 support after current class, size, permission, mechanism
    /// and native entry-point checks. Does not perform crypto or read key values.
    pub fn chacha20_poly1305_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: ChaCha20Poly1305Operation,
    ) -> Result<ChaCha20Poly1305Capabilities, Error> {
        Ok(self
            .session
            .chacha20_poly1305_capabilities(key, operation)?)
    }
    /// Encrypt once using the supplied 12-byte nonce, with a full 16-byte tag.
    /// Returns ciphertext || tag without an envelope. The caller must ensure nonce
    /// uniqueness per key across writers/restarts, including after errors. No nonce
    /// generation, retry or software fallback occurs. Check session closure.
    pub fn encrypt_chacha20_poly1305(
        &mut self,
        key: &ObjectRef,
        request: &ChaCha20Poly1305EncryptRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.encrypt_chacha20_poly1305(key, request)?)
    }
    /// Authenticate/decrypt once. Provider failures return no plaintext and
    /// invalidate the session; preflight rejection does not. Successful plaintext
    /// zeroizes on drop and has redacted Debug.
    /// Native output buffers zeroize on failure and on drop. No retry
    /// or multipart plaintext release occurs. Check closure before releasing output.
    pub fn decrypt_chacha20_poly1305(
        &mut self,
        key: &ObjectRef,
        request: &ChaCha20Poly1305DecryptRequest<'_>,
    ) -> Result<Plaintext, Error> {
        Ok(self.session.decrypt_chacha20_poly1305(key, request)?)
    }
}

impl Client<'_> {
    /// Check current native ChaCha20-Poly1305 support without reading key values.
    pub fn chacha20_poly1305_capabilities(
        &self,
        key: &ObjectRef,
        operation: ChaCha20Poly1305Operation,
        authentication: Authentication<'_>,
    ) -> Result<ChaCha20Poly1305Capabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .chacha20_poly1305_capabilities(key, operation)?)
    }
    /// Encrypt once with caller-managed nonce uniqueness. Never retries or substitutes a mode.
    pub fn encrypt_chacha20_poly1305(
        &self,
        key: &ObjectRef,
        request: &ChaCha20Poly1305EncryptRequest<'_>,
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        request.validate()?;
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .encrypt_chacha20_poly1305(key, request)?)
    }
    /// Authenticate before returning zeroizing plaintext. Native failures discard the pooled session.
    pub fn decrypt_chacha20_poly1305(
        &self,
        key: &ObjectRef,
        request: &ChaCha20Poly1305DecryptRequest<'_>,
        authentication: Authentication<'_>,
    ) -> Result<Plaintext, Error> {
        request.validate()?;
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .decrypt_chacha20_poly1305(key, request)?)
    }
}

impl ManagementSession<'_> {
    /// Generate a protected 256-bit AEAD-only key in RW mode. Bounded identity
    /// and duplicate secret IDs are checked; no retry or rollback occurs. Check closure.
    pub fn generate_chacha20_poly1305_key(
        &mut self,
        request: &ChaCha20Poly1305KeyRequest<'_>,
    ) -> Result<(), Error> {
        Ok(self.session.generate_chacha20_poly1305_key(request)?)
    }
}
