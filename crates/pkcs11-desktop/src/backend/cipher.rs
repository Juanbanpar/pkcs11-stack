// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{
    BackendError, BackendResult, CryptoMode, CryptoScope, LoginState, Registry,
    browse::read_session,
};
use pkcs11_client::{
    DecryptRequest, EncryptRequest, OaepChoice, PrivateKeyRef, PublicKeyRef, RsaCipherOperation,
    SessionState,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

pub struct CipherJob {
    pub choice: OaepChoice,
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
            RsaCipherOperation,
        ),
        BackendError,
    > {
        let (index, uri) = self.location(scope.module, scope.token)?;
        let operation = match scope.mode {
            CryptoMode::Encrypt => RsaCipherOperation::Encrypt,
            CryptoMode::Decrypt => RsaCipherOperation::Decrypt,
            _ => return Err(BackendError::CipherUnavailable),
        };
        let module = &self.modules[index];
        if operation == RsaCipherOperation::Decrypt
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
        let reference = self.reference(scope.module, scope.token, scope.object)?.0;
        Ok((index, uri, reference, operation))
    }
    pub(super) fn cipher_options(&self, scope: CryptoScope) -> Result<BackendResult, BackendError> {
        let (index, uri, reference, operation) = self.cipher_reference(scope)?;
        let module = &self.modules[index];
        let choices = read_session(
            &module.provider,
            &uri,
            module.read_mode(scope.token)?,
            |session| {
                session
                    .oaep_options(&reference, operation)
                    .map_err(|e| cipher_error(&e))
            },
        )?;
        Ok(BackendResult::CipherOptions { scope, choices })
    }
    fn cipher_action(&self, scope: CryptoScope, job: CipherJob) -> Result<(), BackendError> {
        let (index, uri, reference, operation) = self.cipher_reference(scope)?;
        let module = &self.modules[index];
        let limit = if operation == RsaCipherOperation::Encrypt {
            job.choice.maximum_plaintext
        } else {
            job.choice.ciphertext_length
        };
        if limit > 2048 {
            return Err(BackendError::CipherInput);
        }
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
        if operation == RsaCipherOperation::Decrypt && length != limit {
            return Err(BackendError::CipherInput);
        }
        // Reserve a new output before the token operation, then close its session before saving.
        let mut output = super::management::create_output(&job.output)?;
        let bytes = read_session(
            &module.provider,
            &uri,
            module.read_mode(scope.token)?,
            |session| {
                if !session
                    .oaep_options(&reference, operation)
                    .map_err(|e| cipher_error(&e))?
                    .contains(&job.choice)
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
                        let key = PublicKeyRef::new(selector)
                            .map_err(|_| BackendError::CipherUnavailable)?;
                        session
                            .encrypt(
                                &key,
                                &EncryptRequest {
                                    digest: job.choice.digest,
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
                                    digest: job.choice.digest,
                                    ciphertext: input.expose_secret(),
                                },
                            )
                            .map_err(|e| cipher_error(&e))
                    }
                }
            },
        )?;
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
