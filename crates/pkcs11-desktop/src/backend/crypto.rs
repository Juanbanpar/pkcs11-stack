// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{
    BackendError, BackendResult, LoginState, Registry, ResourceId, SecretInput,
    browse::read_session,
};
use pkcs11_client::{
    Certificate, HashLocation, HashingPolicy, MechanismType, ObjectClass, Pin, PrivateKeyRef,
    SessionState, SignInput, SignatureParameters, SigningPolicy,
};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoMode {
    Derive,
    Wrap,
    Unwrap,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoScope {
    pub module: ResourceId,
    pub token: ResourceId,
    pub object: ResourceId,
    pub mode: CryptoMode,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureOption {
    pub parameters: SignatureParameters,
    pub plan: Option<(MechanismType, HashLocation)>,
}
// Contains a one-shot context credential; never formatted or returned to the UI.
pub struct CryptoJob {
    pub parameters: SignatureParameters,
    pub software_hashing: bool,
    pub input: PathBuf,
    pub signature: PathBuf,
    pub context: Option<SecretInput>,
}
fn policy(software: bool) -> SigningPolicy {
    SigningPolicy {
        hashing: if software {
            HashingPolicy::AllowSoftware
        } else {
            HashingPolicy::TokenOnly
        },
        ..SigningPolicy::default()
    }
}
fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, BackendError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| BackendError::CryptoRead)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BackendError::CryptoRead)?;
    if bytes.len() as u64 > maximum {
        return Err(BackendError::CryptoRead);
    }
    Ok(bytes)
}
impl Registry {
    fn signing_location(
        &self,
        scope: CryptoScope,
    ) -> Result<(usize, pkcs11_client::Pkcs11Uri, PrivateKeyRef), BackendError> {
        let (index, uri) = self.location(scope.module, scope.token)?;
        let module = &self.modules[index];
        if !module
            .entry
            .tokens
            .iter()
            .any(|entry| entry.id == scope.token && entry.login == LoginState::User)
            || !module.authentication.iter().any(|(id, session)| {
                *id == scope.token
                    && matches!(
                        session.state(),
                        Ok(SessionState::RoUser | SessionState::RwUser)
                    )
            })
        {
            return Err(BackendError::SigningUnavailable);
        }
        let (reference, class) = self.reference(scope.module, scope.token, scope.object)?;
        if class != Some(ObjectClass::PRIVATE_KEY) {
            return Err(BackendError::SigningUnavailable);
        }
        let uri_key = reference
            .uri()
            .to_string()
            .parse()
            .map_err(|_| BackendError::SigningUnavailable)?;
        Ok((
            index,
            uri,
            PrivateKeyRef::new(uri_key).map_err(|_| BackendError::SigningUnavailable)?,
        ))
    }
    fn verification_certificate(&self, scope: CryptoScope) -> Result<Certificate, BackendError> {
        let (index, uri) = self.location(scope.module, scope.token)?;
        let (reference, class) = self.reference(scope.module, scope.token, scope.object)?;
        if class != Some(ObjectClass::CERTIFICATE) {
            return Err(BackendError::SigningUnavailable);
        }
        let module = &self.modules[index];
        let der = read_session(module, &uri, module.read_mode(scope.token)?, |session| {
            session
                .export_value(&reference)
                .map_err(|e| BackendError::from(&e))
        })?;
        Certificate::from_der(der).map_err(|e| BackendError::from(&e))
    }
    pub(super) fn crypto_options(
        &self,
        scope: CryptoScope,
        software_hashing: bool,
    ) -> Result<BackendResult, BackendError> {
        let (options, context) = match scope.mode {
            CryptoMode::Derive | CryptoMode::Wrap | CryptoMode::Unwrap => {
                return self.key_options(scope);
            }
            CryptoMode::Encrypt | CryptoMode::Decrypt => return self.cipher_options(scope),
            CryptoMode::Sign => {
                let (index, uri, key) = self.signing_location(scope)?;
                let module = &self.modules[index];
                let options =
                    read_session(module, &uri, module.read_mode(scope.token)?, |session| {
                        session
                            .signing_options(&key, &policy(software_hashing))
                            .map_err(|e| BackendError::from(&e))
                    })?;
                (
                    options
                        .choices
                        .into_iter()
                        .map(|choice| SignatureOption {
                            parameters: choice.parameters,
                            plan: Some((choice.mechanism, choice.hashing)),
                        })
                        .collect(),
                    options.always_authenticate,
                )
            }
            CryptoMode::Verify => (
                self.verification_certificate(scope)?
                    .verification_options()
                    .into_iter()
                    .map(|parameters| SignatureOption {
                        parameters,
                        plan: None,
                    })
                    .collect(),
                false,
            ),
        };
        Ok(BackendResult::CryptoOptions {
            scope,
            options,
            context,
        })
    }
    fn sign_file(&self, scope: CryptoScope, job: CryptoJob) -> Result<(), BackendError> {
        let (index, uri, key) = self.signing_location(scope)?;
        let module = &self.modules[index];
        let token = module
            .entry
            .tokens
            .iter()
            .find(|entry| entry.id == scope.token)
            .ok_or(BackendError::UnknownToken)?;
        if matches!(job.context, Some(SecretInput::ProtectedPath)) && !token.protected_path {
            return Err(BackendError::AuthenticationUnavailable);
        }
        let input = read_bounded(&job.input, 16 * 1024 * 1024)?;
        let signature = read_session(module, &uri, module.read_mode(scope.token)?, |session| {
            let policy = policy(job.software_hashing);
            let options = session
                .signing_options(&key, &policy)
                .map_err(|e| BackendError::from(&e))?;
            if !options
                .choices
                .iter()
                .any(|choice| choice.parameters == job.parameters)
            {
                return Err(BackendError::SignatureChoice);
            }
            if options.always_authenticate && job.context.is_none() {
                return Err(BackendError::ContextRequired);
            }
            // Reserve the path only after validating choices, before signing.
            let output = super::management::create_output(&job.signature)?;
            let context = if options.always_authenticate {
                job.context.as_ref().map(|pin| match pin {
                    SecretInput::Value(pin) => Pin::Value(pin),
                    SecretInput::ProtectedPath => Pin::ProtectedPath,
                })
            } else {
                None
            };
            let signature = session
                .sign(
                    &key,
                    &job.parameters.request(SignInput::Message(&input)),
                    &policy,
                    context,
                )
                .map_err(|e| BackendError::from(&e))?;
            Ok((signature, output))
        });
        drop(job.context);
        let (signature, mut output) = signature?;
        output
            .write_all(&signature)
            .and_then(|()| output.flush())
            .map_err(|_| BackendError::FileWrite)
    }
    pub(super) fn crypto(
        &mut self,
        scope: CryptoScope,
        job: CryptoJob,
    ) -> Result<BackendResult, BackendError> {
        if scope.mode == CryptoMode::Verify {
            let certificate = self.verification_certificate(scope)?;
            let input = read_bounded(&job.input, 16 * 1024 * 1024)?;
            let signature = read_bounded(&job.signature, 16 * 1024)?;
            certificate
                .verify_signature(
                    &job.parameters.request(SignInput::Message(&input)),
                    &signature,
                )
                .map_err(|error| match error {
                    pkcs11_client::Error::SignatureMismatch => BackendError::SignatureMismatch,
                    other => BackendError::from(&other),
                })?;
            return Ok(BackendResult::Verified { scope });
        }
        let operation = self.sign_file(scope, job);
        Ok(self.finish_crypto(scope, operation))
    }
    pub(super) fn finish_crypto(
        &mut self,
        scope: CryptoScope,
        operation: Result<(), BackendError>,
    ) -> BackendResult {
        // Failed operations can have effects. Rediscover without retrying.
        let refreshed = self
            .modules
            .iter()
            .position(|entry| entry.entry.id == scope.module)
            .ok_or(BackendError::UnknownModule)
            .and_then(|index| self.discover(index));
        let objects = refreshed.and_then(|()| self.objects(scope.module, scope.token));
        let error = operation.err().or_else(|| {
            objects
                .is_err()
                .then_some(BackendError::RefreshAfterManagement)
        });
        BackendResult::Managed {
            module: scope.module,
            token: scope.token,
            modules: self
                .modules
                .iter()
                .map(|entry| entry.entry.clone())
                .collect(),
            objects: objects.ok(),
            error,
        }
    }
}

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod tests;
