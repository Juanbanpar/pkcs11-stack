// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{
    BackendError, BackendResult, CryptoMode, CryptoScope, LoginState, Registry, ResourceId,
    browse::read_session,
};
use pkcs11_client::{
    AesKeySize, AttributeType, ClassicalPublicKey, DeriveRequest, EcdhPeer, KeyOperation,
    KeyOperationProfile, KeyType, MontgomeryCurve, MontgomeryDerivation, MontgomeryKdf,
    MontgomeryOutput, MontgomeryPublicKey, PrivateKeyRef, SecretKeyIdentity, SessionMode,
    SessionState, UnwrapRequest, WrapRequest,
};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MontgomeryKdfChoice {
    Null,
    X963Sha256,
    X963Sha384,
    X963Sha512,
    Sp80056aSha256,
    Sp80056aSha384,
    Sp80056aSha512,
}
impl MontgomeryKdfChoice {
    pub const ALL: [Self; 7] = [
        Self::Null,
        Self::X963Sha256,
        Self::X963Sha384,
        Self::X963Sha512,
        Self::Sp80056aSha256,
        Self::Sp80056aSha384,
        Self::Sp80056aSha512,
    ];
    pub fn kdf(self) -> MontgomeryKdf {
        match self {
            Self::Null => MontgomeryKdf::Null,
            Self::X963Sha256 => MontgomeryKdf::X963Sha256,
            Self::X963Sha384 => MontgomeryKdf::X963Sha384,
            Self::X963Sha512 => MontgomeryKdf::X963Sha512,
            Self::Sp80056aSha256 => MontgomeryKdf::Sp80056aSha256,
            Self::Sp80056aSha384 => MontgomeryKdf::Sp80056aSha384,
            Self::Sp80056aSha512 => MontgomeryKdf::Sp80056aSha512,
        }
    }
}
impl std::fmt::Display for MontgomeryKdfChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Null => "null",
            Self::X963Sha256 => "X9.63 / SHA-256",
            Self::X963Sha384 => "X9.63 / SHA-384",
            Self::X963Sha512 => "X9.63 / SHA-512",
            Self::Sp80056aSha256 => "SP 800-56A / SHA-256",
            Self::Sp80056aSha384 => "SP 800-56A / SHA-384",
            Self::Sp80056aSha512 => "SP 800-56A / SHA-512",
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MontgomeryOutputChoice {
    Aes128,
    Aes192,
    Aes256,
    DerivationSecret,
}
impl MontgomeryOutputChoice {
    pub const ALL: [Self; 4] = [
        Self::Aes128,
        Self::Aes192,
        Self::Aes256,
        Self::DerivationSecret,
    ];
    pub fn output(self, length: Option<usize>) -> Result<MontgomeryOutput, BackendError> {
        Ok(match self {
            Self::Aes128 => MontgomeryOutput::Aes(AesKeySize::Bits128),
            Self::Aes192 => MontgomeryOutput::Aes(AesKeySize::Bits192),
            Self::Aes256 => MontgomeryOutput::Aes(AesKeySize::Bits256),
            Self::DerivationSecret => MontgomeryOutput::DerivationSecret {
                length: length.ok_or(BackendError::KeyOperationInput)?,
            },
        })
    }
}
impl std::fmt::Display for MontgomeryOutputChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Aes128 => "AES-128",
            Self::Aes192 => "AES-192",
            Self::Aes256 => "AES-256",
            Self::DerivationSecret => "derivation secret",
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProfile {
    Hkdf(pkcs11_client::HkdfCapabilities),
    Classical(KeyOperationProfile),
    MlKem(pkcs11_client::MlKemParameterSet),
    Montgomery(MontgomeryCurve),
}
impl KeyProfile {
    pub fn supports(self, mode: CryptoMode) -> bool {
        matches!(
            (self, mode),
            (Self::Hkdf(_), CryptoMode::Hkdf)
                | (
                    Self::Classical(KeyOperationProfile::EcdhRaw(_)),
                    CryptoMode::Derive
                )
                | (
                    Self::Classical(KeyOperationProfile::AesKeyWrap(_)),
                    CryptoMode::Wrap | CryptoMode::Unwrap
                )
                | (
                    Self::MlKem(_),
                    CryptoMode::Encapsulate | CryptoMode::Decapsulate
                )
                | (Self::Montgomery(_), CryptoMode::Derive)
        )
    }
}
pub enum KeyJob {
    Hkdf(super::HkdfJob),
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
    DeriveMontgomery {
        peer: PathBuf,
        kdf: MontgomeryKdfChoice,
        shared_info: Vec<u8>,
        output: MontgomeryOutputChoice,
        length: Option<usize>,
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
            CryptoMode::Hkdf
                | CryptoMode::Derive
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
            if scope.mode == CryptoMode::Hkdf {
                let choices = session
                    .hkdf_options(&reference)
                    .map_err(|e| BackendError::from(&e))?;
                let [profile] = choices.as_slice() else {
                    return Err(BackendError::KeyOperationUnavailable);
                };
                Ok(KeyProfile::Hkdf(*profile))
            } else if matches!(
                scope.mode,
                CryptoMode::Encapsulate | CryptoMode::Decapsulate
            ) {
                session
                    .ml_kem_capabilities(&reference, super::kem::operation(scope.mode)?)
                    .map(|caps| KeyProfile::MlKem(caps.parameter_set))
                    .map_err(|e| BackendError::from(&e))
            } else {
                let reads = session
                    .inspect(&reference, &[AttributeType::KeyType])
                    .map_err(|e| BackendError::from(&e))?;
                if super::browse::key_type(&reads) == Some(KeyType::EC_MONTGOMERY) {
                    let key = PrivateKeyRef::new(
                        reference
                            .uri()
                            .to_string()
                            .parse()
                            .map_err(|_| BackendError::KeyOperationUnavailable)?,
                    )
                    .map_err(|_| BackendError::KeyOperationUnavailable)?;
                    session
                        .montgomery_private_curve(&key)
                        .map(KeyProfile::Montgomery)
                        .map_err(|e| BackendError::from(&e))
                } else {
                    session
                        .key_operation_options(&reference, operation(scope.mode)?)
                        .map(KeyProfile::Classical)
                        .map_err(|e| BackendError::from(&e))
                }
            }
        })?;
        Ok(BackendResult::KeyOptions { scope, profile })
    }
    fn montgomery_action(
        &self,
        scope: CryptoScope,
        curve: MontgomeryCurve,
        job: KeyJob,
    ) -> Result<(), BackendError> {
        let KeyJob::DeriveMontgomery {
            peer,
            kdf,
            shared_info,
            output,
            length,
            id,
            label,
        } = job
        else {
            return Err(BackendError::KeyOperationUnavailable);
        };
        let (index, uri, reference) = self.key_location(scope)?;
        let bytes = read(&peer, 4096)?;
        let peer = match MontgomeryPublicKey::from_bytes(curve, &bytes) {
            Ok(peer) => peer,
            Err(_) => {
                let parsed = ClassicalPublicKey::from_spki_der(&bytes)
                    .map_err(|_| BackendError::KeyOperationInput)?;
                let peer = parsed
                    .montgomery_public_key()
                    .map_err(|_| BackendError::KeyOperationInput)?;
                if peer.curve() != curve {
                    return Err(BackendError::KeyOperationInput);
                }
                peer
            }
        };
        let output = output.output(length)?;
        let module = &self.modules[index];
        read_session(module, &uri, SessionMode::ReadWrite, |session| {
            session
                .derive_montgomery(
                    &reference,
                    &MontgomeryDerivation {
                        peer: &peer,
                        kdf: kdf.kdf(),
                        shared_info: &shared_info,
                        output,
                        id: &id,
                        label: &label,
                    },
                )
                .map_err(|e| BackendError::from(&e))
        })
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
            KeyProfile::Hkdf(profile) => return self.hkdf_action(scope, profile, job),
            KeyProfile::Classical(profile) => profile,
            KeyProfile::MlKem(parameter) => return self.kem_action(scope, parameter, job),
            KeyProfile::Montgomery(curve) => return self.montgomery_action(scope, curve, job),
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
