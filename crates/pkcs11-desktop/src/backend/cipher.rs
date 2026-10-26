// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{
    BackendError, BackendResult, CryptoMode, CryptoScope, LoginState, Registry,
    browse::read_session,
};
use pkcs11_client::{
    AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_PLAINTEXT, AES_GCM_TAG_LENGTH, AesGcmCapabilities,
    AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmOperation, DecryptRequest, EncryptRequest,
    OaepChoice, ObjectClass, PrivateKeyRef, PublicKeyRef, RsaCipherOperation, SessionState,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherParameters {
    Oaep(OaepChoice),
    AesGcm(AesGcmCapabilities),
}
#[derive(Clone, Copy)]
enum CipherTarget {
    Rsa(RsaCipherOperation),
    AesGcm(AesGcmOperation),
}
pub struct AesGcmFiles {
    pub nonce: [u8; 12],
    pub aad: Option<PathBuf>,
}
pub struct CipherJob {
    pub choice: CipherParameters,
    pub aes_gcm: Option<AesGcmFiles>,
    pub input: PathBuf,
    pub output: PathBuf,
}
fn cipher_error(error: &pkcs11_client::Error) -> BackendError {
    if error.oaep_parameters_rejected() {
        BackendError::OaepParametersRejected
    } else {
        BackendError::from(error)
    }
}
impl Registry {
    fn cipher_reference(
        &self,
        scope: CryptoScope,
    ) -> Result<
        (
            usize,
            pkcs11_client::Pkcs11Uri,
            pkcs11_client::ObjectRef,
            CipherTarget,
        ),
        BackendError,
    > {
        let (index, uri) = self.location(scope.module, scope.token)?;
        let (reference, class) = self.reference(scope.module, scope.token, scope.object)?;
        let target = match (scope.mode, class) {
            (CryptoMode::Encrypt, Some(ObjectClass::PUBLIC_KEY)) => {
                CipherTarget::Rsa(RsaCipherOperation::Encrypt)
            }
            (CryptoMode::Decrypt, Some(ObjectClass::PRIVATE_KEY)) => {
                CipherTarget::Rsa(RsaCipherOperation::Decrypt)
            }
            (CryptoMode::Encrypt, Some(ObjectClass::SECRET_KEY)) => {
                CipherTarget::AesGcm(AesGcmOperation::Encrypt)
            }
            (CryptoMode::Decrypt, Some(ObjectClass::SECRET_KEY)) => {
                CipherTarget::AesGcm(AesGcmOperation::Decrypt)
            }
            _ => return Err(BackendError::CipherUnavailable),
        };
        let module = &self.modules[index];
        if !matches!(target, CipherTarget::Rsa(RsaCipherOperation::Encrypt))
            && (!module
                .entry
                .tokens
                .iter()
                .any(|token| token.id == scope.token && token.login == LoginState::User)
                || !module.authentication.iter().any(|(id, session)| {
                    *id == scope.token
                        && matches!(
                            session.state(),
                            Ok(SessionState::RoUser | SessionState::RwUser)
                        )
                }))
        {
            return Err(BackendError::CipherUnavailable);
        }
        Ok((index, uri, reference, target))
    }
    pub(super) fn cipher_options(&self, scope: CryptoScope) -> Result<BackendResult, BackendError> {
        let (index, uri, reference, operation) = self.cipher_reference(scope)?;
        let module = &self.modules[index];
        let choices = read_session(module, &uri, module.read_mode(scope.token)?, |session| {
            match operation {
                CipherTarget::Rsa(operation) => session
                    .oaep_options(&reference, operation)
                    .map(|choices| choices.into_iter().map(CipherParameters::Oaep).collect()),
                CipherTarget::AesGcm(operation) => session
                    .aes_gcm_capabilities(&reference, operation)
                    .map(|caps| vec![CipherParameters::AesGcm(caps)]),
            }
            .map_err(|e| cipher_error(&e))
        })?;
        Ok(BackendResult::CipherOptions { scope, choices })
    }
    fn cipher_action(&self, scope: CryptoScope, job: CipherJob) -> Result<(), BackendError> {
        let (index, uri, reference, operation) = self.cipher_reference(scope)?;
        let module = &self.modules[index];
        let limit = match (operation, job.choice) {
            (CipherTarget::Rsa(RsaCipherOperation::Encrypt), CipherParameters::Oaep(choice))
                if job.aes_gcm.is_none() && choice.maximum_plaintext <= 2048 =>
            {
                choice.maximum_plaintext
            }
            (CipherTarget::Rsa(RsaCipherOperation::Decrypt), CipherParameters::Oaep(choice))
                if job.aes_gcm.is_none() && choice.ciphertext_length <= 2048 =>
            {
                choice.ciphertext_length
            }
            (CipherTarget::AesGcm(direction), CipherParameters::AesGcm(_))
                if job.aes_gcm.is_some() =>
            {
                AES_GCM_MAXIMUM_PLAINTEXT
                    + if direction == AesGcmOperation::Decrypt {
                        AES_GCM_TAG_LENGTH
                    } else {
                        0
                    }
            }
            _ => return Err(BackendError::CipherInput),
        };
        let aad = match job.aes_gcm.as_ref().and_then(|gcm| gcm.aad.as_ref()) {
            Some(path) => {
                let mut bytes = Vec::new();
                File::open(path)
                    .map_err(|_| BackendError::CipherInput)?
                    .take(AES_GCM_MAXIMUM_AAD as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| BackendError::CipherInput)?;
                if bytes.len() > AES_GCM_MAXIMUM_AAD {
                    return Err(BackendError::CipherInput);
                }
                bytes
            }
            None => Vec::new(),
        };
        // A fixed allocation prevents plaintext copies during Vec growth.
        let mut input = SecretBox::new(Box::new(vec![0; limit + 1]));
        let mut file = File::open(&job.input).map_err(|_| BackendError::CipherInput)?;
        let mut length = 0;
        loop {
            let read = file
                .read(&mut input.expose_secret_mut()[length..])
                .map_err(|_| BackendError::CipherInput)?;
            if read == 0 {
                break;
            }
            length += read;
            if length > limit {
                return Err(BackendError::CipherInput);
            }
        }
        input.expose_secret_mut().truncate(length);
        if (matches!(operation, CipherTarget::Rsa(RsaCipherOperation::Decrypt)) && length != limit)
            || (matches!(operation, CipherTarget::AesGcm(AesGcmOperation::Decrypt))
                && length < AES_GCM_TAG_LENGTH)
        {
            return Err(BackendError::CipherInput);
        }
        // Reserve a new output before the token operation, then close its session before saving.
        let mut output = super::management::create_output(&job.output)?;
        let bytes = read_session(module, &uri, module.read_mode(scope.token)?, |session| {
            if let CipherTarget::AesGcm(direction) = operation {
                let caps = session
                    .aes_gcm_capabilities(&reference, direction)
                    .map_err(|e| cipher_error(&e))?;
                if job.choice != CipherParameters::AesGcm(caps) {
                    return Err(BackendError::CipherUnavailable);
                }
                let gcm = job.aes_gcm.as_ref().ok_or(BackendError::CipherInput)?;
                return match direction {
                    AesGcmOperation::Encrypt => session
                        .encrypt_aes_gcm(
                            &reference,
                            &AesGcmEncryptRequest {
                                nonce: &gcm.nonce,
                                aad: &aad,
                                plaintext: input.expose_secret(),
                            },
                        )
                        .map(|bytes| SecretBox::new(Box::new(bytes))),
                    AesGcmOperation::Decrypt => session.decrypt_aes_gcm(
                        &reference,
                        &AesGcmDecryptRequest {
                            nonce: &gcm.nonce,
                            aad: &aad,
                            ciphertext: input.expose_secret(),
                        },
                    ),
                }
                .map_err(|e| cipher_error(&e));
            }
            let CipherTarget::Rsa(operation) = operation else {
                unreachable!()
            };
            let CipherParameters::Oaep(choice) = job.choice else {
                return Err(BackendError::CipherUnavailable);
            };
            if !session
                .oaep_options(&reference, operation)
                .map_err(|e| cipher_error(&e))?
                .contains(&choice)
            {
                return Err(BackendError::CipherUnavailable);
            }
            let selector = reference
                .uri()
                .to_string()
                .parse()
                .map_err(|_| BackendError::CipherUnavailable)?;
            match operation {
                RsaCipherOperation::Encrypt => {
                    let key =
                        PublicKeyRef::new(selector).map_err(|_| BackendError::CipherUnavailable)?;
                    session
                        .encrypt(
                            &key,
                            &EncryptRequest {
                                digest: choice.digest,
                                plaintext: input.expose_secret(),
                            },
                        )
                        .map(|bytes| SecretBox::new(Box::new(bytes)))
                        .map_err(|e| cipher_error(&e))
                }
                RsaCipherOperation::Decrypt => {
                    let key = PrivateKeyRef::new(selector)
                        .map_err(|_| BackendError::CipherUnavailable)?;
                    session
                        .decrypt(
                            &key,
                            &DecryptRequest {
                                digest: choice.digest,
                                ciphertext: input.expose_secret(),
                            },
                        )
                        .map_err(|e| cipher_error(&e))
                }
            }
        })?;
        output
            .write_all(bytes.expose_secret())
            .and_then(|()| output.flush())
            .map_err(|_| BackendError::FileWrite)
    }
    pub(super) fn cipher(&mut self, scope: CryptoScope, job: CipherJob) -> BackendResult {
        let result = self.cipher_action(scope, job);
        self.finish_crypto(scope, result)
    }
}

#[cfg(test)]
#[path = "cipher_tests.rs"]
mod tests;
