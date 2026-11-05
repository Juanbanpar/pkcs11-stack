// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AesGcmCapabilities, AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmOperation, Error,
    ManagementSession, ObjectRef, Plaintext,
};

/// Exclusive bounded AES-GCM message encryption process. Each message
/// completes independently; `finish` confirms native process termination.
/// Native failure/drop discards the session. No retry or fallback occurs.
#[derive(Debug)]
pub struct AesGcmMessageEncryption<'a>(pkcs11_runtime::AesGcmMessageEncryption<'a>);
impl AesGcmMessageEncryption<'_> {
    /// AES key size checked at initialization.
    pub fn capabilities(&self) -> AesGcmCapabilities {
        self.0.capabilities()
    }
    /// Encrypt one complete message, returning ciphertext || tag. The supplied
    /// nonce must be unique per key across all writers/restarts, including after
    /// errors. Local validation leaves the process active; native errors discard it.
    pub fn encrypt(&mut self, request: &AesGcmEncryptRequest<'_>) -> Result<Vec<u8>, Error> {
        Ok(self.0.encrypt(request)?)
    }
    /// End this process once. Check finalization and session closure before
    /// publishing a batch of results. Only success permits session reuse.
    pub fn finish(self) -> Result<(), Error> {
        Ok(self.0.finish()?)
    }
}

/// Exclusive bounded AES-GCM message decryption process. Each message
/// completes independently; `finish` confirms native process termination.
/// Native failure/drop discards the session. No retry or fallback occurs.
#[derive(Debug)]
pub struct AesGcmMessageDecryption<'a>(pkcs11_runtime::AesGcmMessageDecryption<'a>);
impl AesGcmMessageDecryption<'_> {
    /// AES key size checked at initialization.
    pub fn capabilities(&self) -> AesGcmCapabilities {
        self.0.capabilities()
    }
    /// Authenticate a complete ciphertext || tag before returning zeroizing
    /// plaintext. Local validation leaves the process active; native errors
    /// discard it. Each request supplies the original nonce and AAD.
    pub fn decrypt(&mut self, request: &AesGcmDecryptRequest<'_>) -> Result<Plaintext, Error> {
        Ok(self.0.decrypt(request)?)
    }
    /// End this process once. Check finalization and session closure before
    /// publishing a batch of results. Only success permits session reuse.
    pub fn finish(self) -> Result<(), Error> {
        Ok(self.0.finish()?)
    }
}
impl ManagementSession<'_> {
    /// Inspect message API flags and selected-table pointers independently of
    /// ordinary AES-GCM support, after current key-policy and size checks.
    pub fn aes_gcm_message_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: AesGcmOperation,
    ) -> Result<AesGcmCapabilities, Error> {
        Ok(self.session.aes_gcm_message_capabilities(key, operation)?)
    }
    /// Begin an exclusive process for complete AES-GCM messages. The caller
    /// supplies a unique 12-byte nonce per encryption, including after errors.
    pub fn start_aes_gcm_message_encryption(
        &mut self,
        key: &ObjectRef,
    ) -> Result<AesGcmMessageEncryption<'_>, Error> {
        Ok(AesGcmMessageEncryption(
            self.session.start_aes_gcm_message_encryption(key)?,
        ))
    }
    /// Begin an exclusive process authenticating complete ciphertext || tag
    /// messages. Each successful message returns redacted, zeroizing plaintext.
    ///
    /// ```compile_fail,E0499
    /// use pkcs11_client::{ManagementSession, ObjectRef, Error};
    /// fn overlap(session: &mut ManagementSession<'_>, key: &ObjectRef) -> Result<(), Error> {
    ///     let process = session.start_aes_gcm_message_decryption(key)?;
    ///     session.state()?;
    ///     process.finish()
    /// }
    /// ```
    pub fn start_aes_gcm_message_decryption(
        &mut self,
        key: &ObjectRef,
    ) -> Result<AesGcmMessageDecryption<'_>, Error> {
        Ok(AesGcmMessageDecryption(
            self.session.start_aes_gcm_message_decryption(key)?,
        ))
    }
}
