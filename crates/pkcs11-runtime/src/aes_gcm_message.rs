// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AES_GCM_TAG_LENGTH, AesGcmCapabilities, AesGcmDecryptRequest, AesGcmEncryptRequest,
    AesGcmOperation, Error, ObjectRef, Session,
    aes_gcm::{Api, capabilities},
    error::backend,
};
use cryptoki::mechanism::{
    Mechanism, MessageParam,
    aead::{GcmMessageParams, GeneratorFunction},
};
use secrecy::{ExposeSecretMut, SecretBox};
use std::cell::Cell;

#[derive(Debug)]
struct State<'a> {
    raw: &'a cryptoki::session::Session,
    healthy: &'a Cell<bool>,
    capabilities: AesGcmCapabilities,
    active: bool,
}
impl State<'_> {
    fn accept(&self) -> Result<(), Error> {
        if self.active {
            Ok(())
        } else {
            Err(Error::Closed)
        }
    }
}
/// Exclusive PKCS#11 3.x AES-GCM message encryption process. Each `encrypt`
/// completes one bounded message using an explicit nonce and AAD. Only successful
/// `finish` restores session usability; failure, unwind or drop discards it.
/// Nonce uniqueness per key across all processes/restarts remains the caller's
/// responsibility, including after errors. No retry or fallback occurs.
#[derive(Debug)]
pub struct AesGcmMessageEncryption<'a>(State<'a>);
impl AesGcmMessageEncryption<'_> {
    /// Key size checked before initialization.
    pub fn capabilities(&self) -> AesGcmCapabilities {
        self.0.capabilities
    }
    /// Encrypt one message, returning ciphertext || the full 16-byte tag.
    /// Request bounds are checked before native access; such rejection leaves
    /// this process active. Native failure or malformed output prevents reuse.
    /// No nonce history is retained. Output capacity is fixed before the call.
    pub fn encrypt(&mut self, request: &AesGcmEncryptRequest<'_>) -> Result<Vec<u8>, Error> {
        self.0.accept()?;
        request.validate()?;
        let mut nonce = *request.nonce;
        let mut tag = [0; AES_GCM_TAG_LENGTH];
        let mut params = MessageParam::AesGcmMessage(
            GcmMessageParams::new(
                &mut nonce,
                0.into(),
                GeneratorFunction::NoGenerate,
                &mut tag,
            )
            .map_err(|e| backend("AES GCM message parameters", e))?,
        );
        let mut output = vec![0; request.plaintext.len() + AES_GCM_TAG_LENGTH];
        self.0.active = false;
        let written = self
            .0
            .raw
            .encrypt_message_into(
                &mut params,
                request.aad,
                request.plaintext,
                &mut output[..request.plaintext.len()],
            )
            .map_err(|e| backend("encrypt AES GCM message", e))?;
        if written != request.plaintext.len() || nonce != *request.nonce {
            return Err(Error::InvalidKeyOutput);
        }
        output[written..].copy_from_slice(&tag);
        self.0.active = true;
        Ok(output)
    }
    /// End the message process once. Only native success permits session reuse.
    /// A complete ciphertext may already have been returned by `encrypt`; check
    /// finalization and session closure before publishing a batch of results.
    pub fn finish(mut self) -> Result<(), Error> {
        self.0.accept()?;
        self.0.active = false;
        self.0
            .raw
            .message_encrypt_final()
            .map_err(|e| backend("finalize AES GCM messages", e))?;
        self.0.healthy.set(true);
        Ok(())
    }
}
/// Exclusive PKCS#11 3.x AES-GCM message decryption process. Each `decrypt`
/// authenticates a complete bounded message before returning zeroizing plaintext.
/// Only successful `finish` restores the session; failure/drop discards it.
#[derive(Debug)]
pub struct AesGcmMessageDecryption<'a>(State<'a>);
impl AesGcmMessageDecryption<'_> {
    /// Key size checked before initialization.
    pub fn capabilities(&self) -> AesGcmCapabilities {
        self.0.capabilities
    }
    /// Authenticate one ciphertext || tag. Output storage is exactly ciphertext
    /// length excluding the tag and zeroizes on failure/drop. No output query,
    /// retry, fallback or unauthenticated plaintext release occurs. A native
    /// failure or malformed result prevents further use of this process.
    pub fn decrypt(
        &mut self,
        request: &AesGcmDecryptRequest<'_>,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        self.0.accept()?;
        request.validate()?;
        let length = request.ciphertext.len() - AES_GCM_TAG_LENGTH;
        let mut nonce = *request.nonce;
        let mut tag: [u8; AES_GCM_TAG_LENGTH] = request.ciphertext[length..]
            .try_into()
            .expect("validated tag");
        let original_tag = tag;
        let mut params = MessageParam::AesGcmMessage(
            GcmMessageParams::new(
                &mut nonce,
                0.into(),
                GeneratorFunction::NoGenerate,
                &mut tag,
            )
            .map_err(|e| backend("AES GCM message parameters", e))?,
        );
        let mut output = SecretBox::new(Box::new(vec![0; length]));
        self.0.active = false;
        let written = self
            .0
            .raw
            .decrypt_message_into(
                &mut params,
                request.aad,
                &request.ciphertext[..length],
                output.expose_secret_mut(),
            )
            .map_err(|e| backend("decrypt AES GCM message", e))?;
        if written != length || nonce != *request.nonce || tag != original_tag {
            return Err(Error::InvalidKeyOutput);
        }
        self.0.active = true;
        Ok(output)
    }
    /// End the message process once. Only native success permits session reuse.
    /// Check finalization and session closure before publishing a batch of results.
    pub fn finish(mut self) -> Result<(), Error> {
        self.0.accept()?;
        self.0.active = false;
        self.0
            .raw
            .message_decrypt_final()
            .map_err(|e| backend("finalize AES GCM messages", e))?;
        self.0.healthy.set(true);
        Ok(())
    }
}
impl Session<'_> {
    /// Inspect message API support independently of ordinary AES-GCM operations.
    /// Checks current key policy, size, mechanism message flags and selected-table
    /// pointers. Does not perform cryptography or guarantee provider acceptance.
    pub fn aes_gcm_message_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: AesGcmOperation,
    ) -> Result<AesGcmCapabilities, Error> {
        capabilities(&self.resolve(key)?, operation, Api::Message)
    }
    fn start_aes_gcm_messages(
        &mut self,
        key: &ObjectRef,
        operation: AesGcmOperation,
    ) -> Result<State<'_>, Error> {
        let object = self.resolve(key)?;
        let capabilities = capabilities(&object, operation, Api::Message)?;
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        match operation {
            AesGcmOperation::Encrypt => {
                raw.message_encrypt_init(&Mechanism::AesGcmMessageInit, object.handle)
            }
            AesGcmOperation::Decrypt => {
                raw.message_decrypt_init(&Mechanism::AesGcmMessageInit, object.handle)
            }
        }
        .map_err(|e| backend("initialize AES GCM messages", e))?;
        Ok(State {
            raw,
            healthy: &object.session.healthy,
            capabilities,
            active: true,
        })
    }
    /// Initialize an exclusive process for zero or more complete AES-GCM messages.
    /// Read-only sessions are allowed. Explicit 12-byte nonces are supplied per
    /// message; this process does not generate or track nonces. Call `finish` to
    /// confirm termination before reusing the session. Drop discards the session.
    pub fn start_aes_gcm_message_encryption(
        &mut self,
        key: &ObjectRef,
    ) -> Result<AesGcmMessageEncryption<'_>, Error> {
        Ok(AesGcmMessageEncryption(
            self.start_aes_gcm_messages(key, AesGcmOperation::Encrypt)?,
        ))
    }
    /// Initialize an exclusive process authenticating zero or more complete
    /// AES-GCM messages. Plaintext is released only after each message succeeds.
    /// Read-only sessions are allowed. Call `finish` to confirm termination.
    ///
    /// ```compile_fail,E0499
    /// use pkcs11_runtime::{Session, ObjectRef, Error};
    /// fn overlap(session: &mut Session<'_>, key: &ObjectRef) -> Result<(), Error> {
    ///     let process = session.start_aes_gcm_message_decryption(key)?;
    ///     session.info()?;
    ///     process.finish()
    /// }
    /// ```
    pub fn start_aes_gcm_message_decryption(
        &mut self,
        key: &ObjectRef,
    ) -> Result<AesGcmMessageDecryption<'_>, Error> {
        Ok(AesGcmMessageDecryption(
            self.start_aes_gcm_messages(key, AesGcmOperation::Decrypt)?,
        ))
    }
}
