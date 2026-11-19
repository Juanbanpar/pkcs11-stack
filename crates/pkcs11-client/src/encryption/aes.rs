// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AES_BLOCK_SIZE, AesDecryptRequest, AesDirection, AesEncryptRequest, AesMode, Authentication,
    Client, Error, ManagementSession, ObjectRef, Plaintext,
};

impl Client<'_> {
    /// Encrypt one bounded buffer with an AES key.
    pub fn encrypt_aes(
        &self,
        key: &ObjectRef,
        request: &AesEncryptRequest<'_>,
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .encrypt_aes(key, request)?)
    }

    /// Decrypt one bounded buffer with an AES key, returning redacted plaintext.
    pub fn decrypt_aes(
        &self,
        key: &ObjectRef,
        request: &AesDecryptRequest<'_>,
        authentication: Authentication<'_>,
    ) -> Result<Plaintext, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .decrypt_aes(key, request)?)
    }

    /// Inspect AES mode support for a selected key.
    pub fn aes_capabilities(
        &self,
        key: &ObjectRef,
        mode: AesMode,
        direction: AesDirection,
        authentication: Authentication<'_>,
    ) -> Result<pkcs11_runtime::AesCipherCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .aes_cipher_capabilities(key, mode, direction)?)
    }
}

impl ManagementSession<'_> {
    /// Encrypt one bounded buffer with an AES key.
    pub fn encrypt_aes(
        &mut self,
        key: &ObjectRef,
        request: &AesEncryptRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.encrypt_aes(key, request)?)
    }

    /// Stream AES encryption over chunks.
    pub fn encrypt_aes_chunks<'a>(
        &mut self,
        key: &ObjectRef,
        mode: AesMode,
        iv: Option<&[u8; AES_BLOCK_SIZE]>,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.encrypt_aes_chunks(key, mode, iv, chunks)?)
    }

    /// Decrypt one bounded buffer with an AES key, returning redacted plaintext.
    pub fn decrypt_aes(
        &mut self,
        key: &ObjectRef,
        request: &AesDecryptRequest<'_>,
    ) -> Result<Plaintext, Error> {
        Ok(self.session.decrypt_aes(key, request)?)
    }

    /// Stream AES decryption over chunks.
    pub fn decrypt_aes_chunks<'a>(
        &mut self,
        key: &ObjectRef,
        mode: AesMode,
        iv: Option<&[u8; AES_BLOCK_SIZE]>,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Plaintext, Error> {
        Ok(self.session.decrypt_aes_chunks(key, mode, iv, chunks)?)
    }

    /// Inspect AES mode support for a selected key on this session.
    pub fn aes_capabilities(
        &mut self,
        key: &ObjectRef,
        mode: AesMode,
        direction: AesDirection,
    ) -> Result<pkcs11_runtime::AesCipherCapabilities, Error> {
        Ok(self.session.aes_cipher_capabilities(key, mode, direction)?)
    }
}
