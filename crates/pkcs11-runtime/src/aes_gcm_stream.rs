// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_PLAINTEXT, AES_GCM_NONCE_LENGTH, AES_GCM_TAG_LENGTH,
    AesGcmCapabilities, AesGcmOperation, CancelFlags, Error, Function, ObjectRef, Session,
    error::backend,
};
use cryptoki::mechanism::{Mechanism, aead::GcmParams};
use secrecy::{ExposeSecretMut, SecretBox};
use std::cell::Cell;

/// Multipart AES-GCM parameters: 12-byte nonce, full 16-byte tag and explicit
/// plaintext budget. Debug omits buffers. Nonce/AAD borrows end after native init.
#[derive(Clone, Copy)]
pub struct AesGcmStreamParameters<'a> {
    /// Unique per key across writers/restarts, including after failed encryption.
    /// This API does not generate or track nonces; failure never authorizes reuse.
    pub nonce: &'a [u8; AES_GCM_NONCE_LENGTH],
    /// Authenticated data, at most 1 MiB. Empty is valid.
    pub aad: &'a [u8],
    /// Maximum plaintext bytes, from zero through 16 MiB. Ciphertext includes a
    /// further 16-byte tag. Decryption reserves this budget plus tag storage and
    /// returns no plaintext until final authentication; providers may buffer input.
    pub maximum_plaintext: usize,
}
impl std::fmt::Debug for AesGcmStreamParameters<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcmStreamParameters")
            .field("maximum_plaintext", &self.maximum_plaintext)
            .finish_non_exhaustive()
    }
}
impl AesGcmStreamParameters<'_> {
    /// Validate bounds before provider access. Does not establish nonce uniqueness.
    pub fn validate(&self) -> Result<(), Error> {
        if self.aad.len() > AES_GCM_MAXIMUM_AAD
            || self.maximum_plaintext > AES_GCM_MAXIMUM_PLAINTEXT
        {
            return Err(Error::InvalidParameters("AES GCM stream bounds"));
        }
        Ok(())
    }
}
struct State<'a> {
    raw: &'a cryptoki::session::Session,
    healthy: &'a Cell<bool>,
    operation: AesGcmOperation,
    capabilities: AesGcmCapabilities,
    input: usize,
    maximum: usize,
    active: bool,
    cancellation_supported: bool,
}
impl std::fmt::Debug for State<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcmOperation")
            .field("operation", &self.operation)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}
impl Drop for State<'_> {
    fn drop(&mut self) {
        if self.active {
            self.healthy.set(false);
        }
    }
}
impl State<'_> {
    fn accept(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        match self.input.checked_add(bytes.len()) {
            Some(total) if total <= self.maximum => {
                self.input = total;
                Ok(())
            }
            _ => {
                self.active = false;
                Err(Error::InvalidParameters("AES GCM stream input limit"))
            }
        }
    }
    fn complete(&mut self) {
        self.active = false;
        self.healthy.set(true);
    }
    fn cancel(mut self) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        let flags = match self.operation {
            AesGcmOperation::Encrypt => CancelFlags::ENCRYPT,
            AesGcmOperation::Decrypt => CancelFlags::DECRYPT,
        };
        crate::cancellation::cancel(self.raw, self.cancellation_supported, flags)?;
        self.complete();
        Ok(())
    }
}
/// Exclusive AES-GCM encryption. Updates return ciphertext; finish returns the
/// remaining ciphertext and tag. Drop/failure discards incomplete sessions.
#[derive(Debug)]
pub struct AesGcmEncryption<'a> {
    state: State<'a>,
    emitted: usize,
}
impl AesGcmEncryption<'_> {
    /// Current AES key size, checked before initialization.
    pub fn capabilities(&self) -> AesGcmCapabilities {
        self.state.capabilities
    }
    /// Encrypt one chunk, including empty input, with bounded output. No length
    /// queries or retries occur. The configured total input budget applies.
    pub fn update(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        self.state.accept(bytes)?;
        let pending = self.state.input - self.emitted;
        let mut output = vec![0; pending + AES_GCM_TAG_LENGTH];
        match self.state.raw.encrypt_update_into(bytes, &mut output) {
            Ok(written) if written <= pending => {
                self.emitted += written;
                output.truncate(written);
                Ok(output)
            }
            result => {
                self.state.active = false;
                match result {
                    Err(error) => Err(backend("update AES GCM encryption", error)),
                    Ok(_) => Err(Error::InvalidKeyOutput),
                }
            }
        }
    }
    /// Complete once and return the remaining ciphertext || full tag. Concatenate
    /// with earlier updates. Check session closure before publishing the result.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        if !self.state.active {
            return Err(Error::Closed);
        }
        let mut output = vec![0; self.state.input + AES_GCM_TAG_LENGTH - self.emitted];
        let written = self
            .state
            .raw
            .encrypt_final_into(&mut output)
            .map_err(|e| backend("finish AES GCM encryption", e))?;
        if written != output.len() {
            return Err(Error::InvalidKeyOutput);
        }
        self.state.complete();
        Ok(output)
    }
    /// Cancel once. Only confirmed native termination permits reuse; no implicit
    /// cancellation occurs. The nonce still must not be reused after cancellation.
    pub fn cancel(self) -> Result<(), Error> {
        self.state.cancel()
    }
}
/// Exclusive authenticated AES-GCM decryption. Updates expose no plaintext.
/// Secret storage zeroizes on failure/drop, including bytes written before an
/// error. Any plaintext returned by native updates is quarantined until final
/// authentication succeeds, following the release boundary in section 6.13.2.
#[derive(Debug)]
pub struct AesGcmDecryption<'a> {
    state: State<'a>,
    output: SecretBox<Vec<u8>>,
    produced: usize,
}
impl AesGcmDecryption<'_> {
    /// Current AES key size, checked before initialization.
    pub fn capabilities(&self) -> AesGcmCapabilities {
        self.state.capabilities
    }
    /// Supply ciphertext || tag chunks, with arbitrary splits, including empty
    /// input and split tags. Native update plaintext stays in zeroizing quarantine.
    /// Failure discards the session and wipes the whole buffer before returning.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if let Err(error) = self.state.accept(bytes) {
            self.output.expose_secret_mut().fill(0);
            return Err(error);
        }
        match self.state.raw.decrypt_update_into(
            bytes,
            &mut self.output.expose_secret_mut()[self.produced..self.state.input],
        ) {
            Ok(written) if self.produced + written <= self.state.maximum - AES_GCM_TAG_LENGTH => {
                self.produced += written;
                Ok(())
            }
            result => {
                self.state.active = false;
                self.output.expose_secret_mut().fill(0);
                match result {
                    Err(error) => Err(backend("update AES GCM decryption", error)),
                    Ok(_) => Err(Error::InvalidKeyOutput),
                }
            }
        }
    }

    /// Authenticate once and return redacted, zeroizing plaintext only on success
    /// and exact-length validation. Failure returns no plaintext and discards the
    /// session. Check closure before releasing the result to a destination.
    pub fn finish(mut self) -> Result<SecretBox<Vec<u8>>, Error> {
        if !self.state.active {
            return Err(Error::Closed);
        }
        if self.state.input < AES_GCM_TAG_LENGTH {
            return Err(Error::InvalidParameters(
                "AES GCM ciphertext is shorter than its tag",
            ));
        }
        let written = self
            .state
            .raw
            .decrypt_final_into(
                &mut self.output.expose_secret_mut()[self.produced..self.state.input],
            )
            .map_err(|e| backend("finish AES GCM decryption", e))?;
        let written = self.produced + written;
        if written != self.state.input - AES_GCM_TAG_LENGTH {
            return Err(Error::InvalidKeyOutput);
        }
        self.output.expose_secret_mut()[written..].fill(0);
        self.output.expose_secret_mut().truncate(written);
        self.state.complete();
        Ok(std::mem::replace(
            &mut self.output,
            SecretBox::new(Box::new(Vec::new())),
        ))
    }
    /// Cancel once; secret storage zeroizes. Only confirmed native termination
    /// permits session reuse. Failed/unsupported cancellation requires closure.
    pub fn cancel(self) -> Result<(), Error> {
        self.state.cancel()
    }
}
impl Session<'_> {
    /// Inspect AES-GCM multipart support independently of single-part pointers.
    pub fn aes_gcm_streaming_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: AesGcmOperation,
    ) -> Result<AesGcmCapabilities, Error> {
        crate::aes_gcm::capabilities(
            &self.resolve(key)?,
            operation,
            crate::aes_gcm::Api::Multipart,
        )
    }
    fn start_aes_gcm(
        &mut self,
        key: &ObjectRef,
        parameters: AesGcmStreamParameters<'_>,
        operation: AesGcmOperation,
    ) -> Result<State<'_>, Error> {
        parameters.validate()?;
        let object = self.resolve(key)?;
        let capabilities =
            crate::aes_gcm::capabilities(&object, operation, crate::aes_gcm::Api::Multipart)?;
        let mut nonce = *parameters.nonce;
        let params = GcmParams::new(&mut nonce, parameters.aad, 128.into())
            .map_err(|e| backend("AES GCM stream parameters", e))?;
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        match operation {
            AesGcmOperation::Encrypt => raw.encrypt_init(&Mechanism::AesGcm(params), object.handle),
            AesGcmOperation::Decrypt => raw.decrypt_init(&Mechanism::AesGcm(params), object.handle),
        }
        .map_err(|e| backend("initialize AES GCM stream", e))?;
        if nonce != *parameters.nonce {
            return Err(Error::InvalidKeyOutput);
        }
        Ok(State {
            raw,
            healthy: &object.session.healthy,
            operation,
            capabilities,
            input: 0,
            maximum: parameters.maximum_plaintext
                + if matches!(operation, AesGcmOperation::Decrypt) {
                    AES_GCM_TAG_LENGTH
                } else {
                    0
                },
            active: true,
            cancellation_supported: object
                .session
                .token()
                .module
                .supports_function(Function::SessionCancel),
        })
    }
    /// Begin exclusive AES-GCM encryption. Input is bounded by the supplied budget
    /// (at most 16 MiB); no whole-input copy is retained by this guard. Nonce/AAD
    /// borrows end after init. No nonce generation, retry or fallback occurs.
    pub fn start_aes_gcm_encryption(
        &mut self,
        key: &ObjectRef,
        parameters: AesGcmStreamParameters<'_>,
    ) -> Result<AesGcmEncryption<'_>, Error> {
        Ok(AesGcmEncryption {
            state: self.start_aes_gcm(key, parameters, AesGcmOperation::Encrypt)?,
            emitted: 0,
        })
    }
    /// Begin exclusive AES-GCM decryption. A bounded zeroizing scratch buffer is
    /// reserved before native init. Plaintext is withheld until final authentication;
    /// no temporary plaintext file or output callback is used. Nonce/AAD borrows
    /// end after init. Failures/drop discard the session; no retry or fallback.
    pub fn start_aes_gcm_decryption(
        &mut self,
        key: &ObjectRef,
        parameters: AesGcmStreamParameters<'_>,
    ) -> Result<AesGcmDecryption<'_>, Error> {
        parameters.validate()?;
        let output = SecretBox::new(Box::new(vec![
            0;
            parameters.maximum_plaintext
                + AES_GCM_TAG_LENGTH
        ]));
        Ok(AesGcmDecryption {
            state: self.start_aes_gcm(key, parameters, AesGcmOperation::Decrypt)?,
            output,
            produced: 0,
        })
    }
}

#[cfg(all(test, unix))]
#[path = "../tests/fixtures/aes_gcm_stream_module.rs"]
mod fixture;
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    #[test]
    fn failed_update_wipes_provider_written_plaintext_before_returning() {
        for fault in [17, 18, 19, 26, 33, 38] {
            let fixture = super::fixture::AesGcmStreamModule::new(3, 2, fault, 16, 0);
            let module = crate::Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(crate::SessionMode::ReadOnly).unwrap();
            let key = ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap())
                .unwrap();
            let parameters = AesGcmStreamParameters {
                nonce: &[0xA5; 12],
                aad: &[],
                maximum_plaintext: 3,
            };
            let mut operation = session.start_aes_gcm_decryption(&key, parameters).unwrap();
            assert!(operation.update(&[0xEF; 19]).is_err());
            assert!(
                operation
                    .output
                    .expose_secret()
                    .iter()
                    .all(|&byte| byte == 0)
            );
            assert!(!operation.state.healthy.get());
            assert!(matches!(operation.update(&[]), Err(Error::Closed)));
            drop(operation);
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
    #[test]
    fn later_update_failure_wipes_all_quarantined_plaintext() {
        let fixture = super::fixture::AesGcmStreamModule::new(3, 2, 37, 16, 0);
        let module = crate::Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(crate::SessionMode::ReadOnly).unwrap();
        let key =
            ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap();
        let parameters = AesGcmStreamParameters {
            nonce: &[0xA5; 12],
            aad: &[],
            maximum_plaintext: 3,
        };
        let mut operation = session.start_aes_gcm_decryption(&key, parameters).unwrap();
        operation.update(&[0xEF; 17]).unwrap();
        assert_eq!(operation.produced, 1);
        assert_eq!(operation.output.expose_secret()[0], b'a');
        assert!(operation.update(&[0xEF; 2]).is_err());
        assert!(
            operation
                .output
                .expose_secret()
                .iter()
                .all(|&byte| byte == 0)
        );
        drop(operation);
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
