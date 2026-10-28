// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AES_GCM_TAG_LENGTH, AesGcmCapabilities, AesGcmOperation, AesGcmStreamParameters, Error,
    ManagementSession, ObjectRef, Plaintext, input::read_chunks,
};
/// Exclusive bounded AES-GCM encryptor. Drop discards incomplete sessions. Nonce
/// reuse remains forbidden after errors/cancellation; no fallback or retry occurs.
#[derive(Debug)]
pub struct AesGcmEncryption<'a>(pkcs11_runtime::AesGcmEncryption<'a>);
impl AesGcmEncryption<'_> {
    /// Current AES key size, checked at initialization.
    pub fn capabilities(&self) -> AesGcmCapabilities {
        self.0.capabilities()
    }
    /// Encrypt a chunk. The configured total plaintext budget applies.
    pub fn update(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.update(bytes)?)
    }
    /// Complete once. Concatenate returned bytes with earlier update ciphertext.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        Ok(self.0.finish()?)
    }
    /// Cancel once; only confirmed native termination permits reuse.
    pub fn cancel(self) -> Result<(), Error> {
        Ok(self.0.cancel()?)
    }
}
/// Exclusive authenticated AES-GCM decryptor. No plaintext is exposed by updates.
/// Secret storage zeroizes on failure/drop; incomplete sessions are discarded.
#[derive(Debug)]
pub struct AesGcmDecryption<'a>(pkcs11_runtime::AesGcmDecryption<'a>);
impl AesGcmDecryption<'_> {
    /// Current AES key size, checked at initialization.
    pub fn capabilities(&self) -> AesGcmCapabilities {
        self.0.capabilities()
    }
    /// Supply ciphertext/tag chunks. Native failure prevents further use.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        Ok(self.0.update(bytes)?)
    }
    /// Authenticate once, then return redacted, zeroizing plaintext. Check session
    /// closure before publishing. No plaintext is returned after authentication failure.
    pub fn finish(self) -> Result<Plaintext, Error> {
        Ok(self.0.finish()?)
    }
    /// Cancel once; secret storage zeroizes. Only confirmed native termination permits reuse.
    pub fn cancel(self) -> Result<(), Error> {
        Ok(self.0.cancel()?)
    }
}
impl ManagementSession<'_> {
    /// Inspect multipart AES-GCM support independently of single-part entry points.
    pub fn aes_gcm_streaming_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: AesGcmOperation,
    ) -> Result<AesGcmCapabilities, Error> {
        Ok(self
            .session
            .aes_gcm_streaming_capabilities(key, operation)?)
    }
    /// Begin exclusive bounded AES-GCM encryption. Nonce/AAD borrows end at init;
    /// nonce uniqueness across writers/restarts is the caller's responsibility.
    pub fn start_aes_gcm_encryption(
        &mut self,
        key: &ObjectRef,
        parameters: AesGcmStreamParameters<'_>,
    ) -> Result<AesGcmEncryption<'_>, Error> {
        Ok(AesGcmEncryption(
            self.session.start_aes_gcm_encryption(key, parameters)?,
        ))
    }
    /// Begin exclusive authenticated AES-GCM decryption, reserving the bounded
    /// plaintext budget plus tag storage. Nonce/AAD borrows end at init. Failures
    /// return no plaintext; no plaintext staging file or output callback is used.
    ///
    /// ```compile_fail,E0499
    /// use pkcs11_client::{AesGcmStreamParameters, Error, ManagementSession, ObjectRef};
    /// fn overlap(session: &mut ManagementSession<'_>, key: &ObjectRef, parameters: AesGcmStreamParameters<'_>) -> Result<(), Error> {
    ///     let mut operation = session.start_aes_gcm_decryption(key, parameters)?;
    ///     session.start_aes_gcm_encryption(key, parameters)?;
    ///     operation.update(b"ciphertext")?;
    ///     Ok(())
    /// }
    /// ```
    pub fn start_aes_gcm_decryption(
        &mut self,
        key: &ObjectRef,
        parameters: AesGcmStreamParameters<'_>,
    ) -> Result<AesGcmDecryption<'_>, Error> {
        Ok(AesGcmDecryption(
            self.session.start_aes_gcm_decryption(key, parameters)?,
        ))
    }
    /// Encrypt a reader through a zeroizing 64 KiB input buffer. Empty input and
    /// Interrupted reads are supported. Returns ciphertext || tag only after
    /// finalization; the explicit budget is at most 16 MiB. No nonce generation,
    /// retry or fallback occurs. Check closure before publishing the result.
    pub fn encrypt_aes_gcm_reader(
        &mut self,
        key: &ObjectRef,
        parameters: AesGcmStreamParameters<'_>,
        reader: &mut impl std::io::Read,
    ) -> Result<Vec<u8>, Error> {
        let mut operation = self.start_aes_gcm_encryption(key, parameters)?;
        let mut output = Vec::with_capacity(parameters.maximum_plaintext + AES_GCM_TAG_LENGTH);
        read_chunks(
            reader,
            |bytes| {
                output.extend(operation.update(bytes)?);
                Ok(())
            },
            Error::CipherInput,
        )?;
        output.extend(operation.finish()?);
        Ok(output)
    }
    /// Authenticate/decrypt a reader with a zeroizing 64 KiB input buffer. Only
    /// successful final authentication returns plaintext, in redacted, zeroizing
    /// memory bounded by the explicit budget (at most 16 MiB). Split tags and
    /// Interrupted reads are supported. Read/native/drop failures discard the
    /// session. Check closure before writing the result to a destination.
    pub fn decrypt_aes_gcm_reader(
        &mut self,
        key: &ObjectRef,
        parameters: AesGcmStreamParameters<'_>,
        reader: &mut impl std::io::Read,
    ) -> Result<Plaintext, Error> {
        let mut operation = self.start_aes_gcm_decryption(key, parameters)?;
        read_chunks(reader, |bytes| operation.update(bytes), Error::CipherInput)?;
        operation.finish()
    }
}
