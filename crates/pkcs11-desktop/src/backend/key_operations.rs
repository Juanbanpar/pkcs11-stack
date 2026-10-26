// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{
    BackendError, BackendResult, CryptoMode, CryptoScope, LoginState, Registry, ResourceId,
    browse::read_session,
};
use pkcs11_client::{
    DeriveRequest, EcdhPeer, KeyOperation, KeyOperationProfile, SecretKeyIdentity, SessionMode,
    SessionState, UnwrapRequest, WrapRequest,
};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProfile {
    Classical(KeyOperationProfile),
    MlKem(pkcs11_client::MlKemParameterSet),
}
impl KeyProfile {
    pub fn supports(self, mode: CryptoMode) -> bool {
        matches!(
            (self, mode),
            (
                Self::Classical(KeyOperationProfile::EcdhRaw(_)),
                CryptoMode::Derive
            ) | (
                Self::Classical(KeyOperationProfile::AesKeyWrap(_)),
                CryptoMode::Wrap | CryptoMode::Unwrap
            ) | (
                Self::MlKem(_),
                CryptoMode::Encapsulate | CryptoMode::Decapsulate
            )
        )
    }
}
pub enum KeyJob {
    Encapsulate {
        output: PathBuf,
        id: Vec<u8>,
        label: Vec<u8>,
    },
    Decapsulate {
        input: PathBuf,
        id: Vec<u8>,
        label: Vec<u8>,
    },
    Derive {
        peer: PathBuf,
        id: Vec<u8>,
        label: Vec<u8>,
    },
    Wrap {
        target: ResourceId,
        output: PathBuf,
    },
    Unwrap {
        input: PathBuf,
        id: Vec<u8>,
        label: Vec<u8>,
    },
}
pub fn operation(mode: CryptoMode) -> Result<KeyOperation, BackendError> {
    match mode {
        CryptoMode::Derive => Ok(KeyOperation::Derive),
        CryptoMode::Wrap => Ok(KeyOperation::Wrap),
        CryptoMode::Unwrap => Ok(KeyOperation::Unwrap),
        _ => Err(BackendError::KeyOperationUnavailable),
    }
}
pub(super) fn read(path: &Path, limit: u64) -> Result<Vec<u8>, BackendError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| BackendError::KeyOperationInput)?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BackendError::KeyOperationInput)?;
    if bytes.len() as u64 > limit {
        return Err(BackendError::KeyOperationInput);
    }
    Ok(bytes)
}
impl Registry {
    pub(super) fn key_location(
        &self,
        scope: CryptoScope,
    ) -> Result<(usize, pkcs11_client::Pkcs11Uri, pkcs11_client::ObjectRef), BackendError> {
        if !matches!(
            scope.mode,
            CryptoMode::Derive
                | CryptoMode::Wrap
                | CryptoMode::Unwrap
                | CryptoMode::Encapsulate
                | CryptoMode::Decapsulate
        ) {
            return Err(BackendError::KeyOperationUnavailable);
        }
        let (index, uri) = self.location(scope.module, scope.token)?;
        let module = &self.modules[index];
        let token = module
            .entry
            .tokens
            .iter()
            .find(|entry| entry.id == scope.token)
            .ok_or(BackendError::UnknownToken)?;
        if token.login != LoginState::User
            || (scope.mode != CryptoMode::Wrap && !token.can_manage())
            || !module.authentication.iter().any(|(id, session)| {
                *id == scope.token
                    && matches!(
                        session.state(),
                        Ok(SessionState::RoUser | SessionState::RwUser)
                    )
            })
        {
            return Err(BackendError::KeyOperationUnavailable);
        }
        let reference = self.reference(scope.module, scope.token, scope.object)?.0;
        Ok((index, uri, reference))
    }
    pub(super) fn key_options(&self, scope: CryptoScope) -> Result<BackendResult, BackendError> {
        let (index, uri, reference) = self.key_location(scope)?;
        let module = &self.modules[index];
        let profile = read_session(module, &uri, module.read_mode(scope.token)?, |session| {
            if matches!(
                scope.mode,
                CryptoMode::Encapsulate | CryptoMode::Decapsulate
            ) {
                session
                    .ml_kem_capabilities(&reference, super::kem::operation(scope.mode)?)
                    .map(|caps| KeyProfile::MlKem(caps.parameter_set))
                    .map_err(|e| BackendError::from(&e))
            } else {
                session
                    .key_operation_options(&reference, operation(scope.mode)?)
                    .map(KeyProfile::Classical)
                    .map_err(|e| BackendError::from(&e))
            }
        })?;
        Ok(BackendResult::KeyOptions { scope, profile })
    }
    fn key_action(
        &self,
        scope: CryptoScope,
        selected: KeyProfile,
        job: KeyJob,
    ) -> Result<(), BackendError> {
        if !selected.supports(scope.mode) {
            return Err(BackendError::KeyOperationUnavailable);
        }
        let selected = match selected {
            KeyProfile::Classical(profile) => profile,
            KeyProfile::MlKem(parameter) => return self.kem_action(scope, parameter, job),
        };
        let (index, uri, reference) = self.key_location(scope)?;
        let operation = operation(scope.mode)?;
        let module = &self.modules[index];
        let mode = if operation == KeyOperation::Wrap {
            module.read_mode(scope.token)?
        } else {
            SessionMode::ReadWrite
        };
        match (operation, job) {
            (KeyOperation::Derive, KeyJob::Derive { peer, id, label }) => {
                let peer = EcdhPeer::from_spki_der(&read(&peer, 1024)?)
                    .map_err(|_| BackendError::KeyOperationInput)?;
                read_session(module, &uri, mode, |session| {
                    if session
                        .key_operation_options(&reference, operation)
                        .map_err(|e| BackendError::from(&e))?
                        != selected
                    {
                        return Err(BackendError::KeyOperationUnavailable);
                    }
                    session
                        .derive(
                            &reference,
                            &DeriveRequest {
                                peer: &peer,
                                identity: SecretKeyIdentity {
                                    id: &id,
                                    label: &label,
                                },
                            },
                        )
                        .map_err(|e| BackendError::from(&e))
                })
            }
            (KeyOperation::Wrap, KeyJob::Wrap { target, output }) => {
                let target = self.reference(scope.module, scope.token, target)?.0;
                let mut output = super::management::create_output(&output)?;
                let bytes = read_session(module, &uri, mode, |session| {
                    if session
                        .key_operation_options(&reference, operation)
                        .map_err(|e| BackendError::from(&e))?
                        != selected
                    {
                        return Err(BackendError::KeyOperationUnavailable);
                    }
                    session
                        .wrap(&reference, &WrapRequest { target: &target })
                        .map_err(|e| BackendError::from(&e))
                })?;
                output
                    .write_all(&bytes)
                    .and_then(|()| output.flush())
                    .map_err(|_| BackendError::FileWrite)
            }
            (KeyOperation::Unwrap, KeyJob::Unwrap { input, id, label }) => {
                let bytes = read(&input, 40)?;
                if ![24, 32, 40].contains(&bytes.len()) {
                    return Err(BackendError::KeyOperationInput);
                }
                read_session(module, &uri, mode, |session| {
                    if session
                        .key_operation_options(&reference, operation)
                        .map_err(|e| BackendError::from(&e))?
                        != selected
                    {
                        return Err(BackendError::KeyOperationUnavailable);
                    }
                    session
                        .unwrap(
                            &reference,
                            &UnwrapRequest {
                                wrapped: &bytes,
                                identity: SecretKeyIdentity {
                                    id: &id,
                                    label: &label,
                                },
                            },
                        )
                        .map_err(|e| BackendError::from(&e))
                })
            }
            _ => Err(BackendError::KeyOperationUnavailable),
        }
    }
    pub(super) fn key_operation(
        &mut self,
        scope: CryptoScope,
        profile: KeyProfile,
        job: KeyJob,
    ) -> BackendResult {
        let result = self.key_action(scope, profile, job);
        self.finish_crypto(scope, result)
    }
}
#[cfg(test)]
#[path = "key_operations_tests.rs"]
mod tests;
