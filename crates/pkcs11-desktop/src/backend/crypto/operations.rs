// SPDX-License-Identifier: MIT OR Apache-2.0
use super::certificate::VerificationCertificate;

use super::options::{public_verification_options, signing_options};

use super::super::{
    BackendError, BackendResult, LoginState, SecretInput, browse::read_session, management,
    registry::Registry,
};
use pkcs11_client::{
    EdDsaRequest, HashInput, HashMlDsaRequest, HashMlDsaSigningPolicy, HashSlhDsaRequest,
    HashSlhDsaSigningPolicy, HashingPolicy, MlDsaHedging, MlDsaRequest, MlDsaSigningPolicy,
    ObjectClass, Pin, PrehashAlgorithm, PrivateKeyRef, PublicKeyRef, SessionState, SignInput,
    SigningPolicy, SlhDsaHedging, SlhDsaRequest, SlhDsaSigningPolicy, VerifyRequest,
};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use super::{CryptoJob, CryptoMode, CryptoScope, SignatureOption, SignatureProfile};

pub(super) fn policy(software: bool) -> SigningPolicy {
    SigningPolicy {
        hashing: if software {
            HashingPolicy::AllowSoftware
        } else {
            HashingPolicy::TokenOnly
        },
        ..SigningPolicy::default()
    }
}
pub(super) fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, BackendError> {
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
fn hash_input<'a>(hash: PrehashAlgorithm, prehashed: bool, bytes: &'a [u8]) -> HashInput<'a> {
    if prehashed {
        HashInput::Digest { hash, bytes }
    } else {
        HashInput::Message {
            hash,
            message: bytes,
        }
    }
}

fn validate_hash_input(profile: SignatureProfile, input_len: usize) -> Result<(), BackendError> {
    match profile {
        SignatureProfile::HashMlDsa {
            hash, prehashed, ..
        }
        | SignatureProfile::HashSlhDsa {
            hash, prehashed, ..
        } if prehashed && input_len != hash.output_len() => Err(BackendError::SignatureChoice),
        _ => Ok(()),
    }
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
            .to_secret_uri()
            .expose_secret()
            .parse()
            .map_err(|_| BackendError::SigningUnavailable)?;
        Ok((
            index,
            uri,
            PrivateKeyRef::new(uri_key).map_err(|_| BackendError::SigningUnavailable)?,
        ))
    }
    fn verification_certificate(
        &self,
        scope: CryptoScope,
    ) -> Result<VerificationCertificate, BackendError> {
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
        VerificationCertificate::from_der(der)
    }
    fn public_verification_options(
        &self,
        scope: CryptoScope,
    ) -> Result<Vec<SignatureOption>, BackendError> {
        let (index, uri) = self.location(scope.module, scope.token)?;
        let (reference, class) = self.reference(scope.module, scope.token, scope.object)?;
        if class != Some(ObjectClass::PUBLIC_KEY) {
            return Err(BackendError::SigningUnavailable);
        }
        let key = PublicKeyRef::new(
            reference
                .uri()
                .to_secret_uri()
                .expose_secret()
                .parse()
                .map_err(|_| BackendError::SigningUnavailable)?,
        )
        .map_err(|_| BackendError::SigningUnavailable)?;
        let module = &self.modules[index];
        read_session(module, &uri, module.read_mode(scope.token)?, |session| {
            public_verification_options(session, &key)
        })
    }

    fn verify_public_file(&self, scope: CryptoScope, job: CryptoJob) -> Result<(), BackendError> {
        match job.parameters {
            SignatureProfile::HashMlDsa { .. } if job.software_hashing => {
                return Err(BackendError::SignatureChoice);
            }
            SignatureProfile::HashSlhDsa { .. } | SignatureProfile::SlhDsa(_)
                if job.software_hashing =>
            {
                return Err(BackendError::SignatureChoice);
            }
            SignatureProfile::SlhDsa(_) | SignatureProfile::HashSlhDsa { .. }
                if job.domain_context.len() > 255 =>
            {
                return Err(BackendError::PqcContext);
            }
            SignatureProfile::HashMlDsa { .. } if job.domain_context.len() > 255 => {
                return Err(BackendError::MlDsaContext);
            }
            SignatureProfile::EdDsa(_) if !job.domain_context.is_empty() => {
                return Err(BackendError::SignatureChoice);
            }
            SignatureProfile::Classical(_) if !job.domain_context.is_empty() => {
                return Err(BackendError::SignatureChoice);
            }
            _ => {}
        }
        let (index, uri) = self.location(scope.module, scope.token)?;
        let (reference, class) = self.reference(scope.module, scope.token, scope.object)?;
        if class != Some(ObjectClass::PUBLIC_KEY) {
            return Err(BackendError::SigningUnavailable);
        }
        let key = PublicKeyRef::new(
            reference
                .uri()
                .to_secret_uri()
                .expose_secret()
                .parse()
                .map_err(|_| BackendError::SigningUnavailable)?,
        )
        .map_err(|_| BackendError::SigningUnavailable)?;
        let input = read_bounded(&job.input, 16 * 1024 * 1024)?;
        let signature = read_bounded(&job.signature, 64 * 1024)?;
        validate_hash_input(job.parameters, input.len())?;
        let module = &self.modules[index];
        read_session(module, &uri, module.read_mode(scope.token)?, |session| {
            match job.parameters {
                SignatureProfile::Classical(parameters) => session.verify_token(
                    &key,
                    &VerifyRequest {
                        parameters: parameters.request(SignInput::Message(&input)),
                        signature: &signature,
                    },
                    &policy(job.software_hashing),
                ),
                SignatureProfile::MlDsa(parameter_set) => session.verify_ml_dsa(
                    &key,
                    &MlDsaRequest {
                        parameter_set,
                        message: &input,
                        context: &job.domain_context,
                        hedging: MlDsaHedging::Deterministic,
                    },
                    &signature,
                ),
                SignatureProfile::EdDsa(curve) => session.verify_eddsa(
                    &key,
                    &EdDsaRequest {
                        curve,
                        message: &input,
                    },
                    &signature,
                ),
                SignatureProfile::SlhDsa(parameter_set) => session.verify_slh_dsa(
                    &key,
                    &SlhDsaRequest {
                        parameter_set,
                        message: &input,
                        context: &job.domain_context,
                        hedging: SlhDsaHedging::Deterministic,
                    },
                    &signature,
                ),
                SignatureProfile::HashMlDsa {
                    parameter_set,
                    hash,
                    prehashed,
                } => session.verify_hash_ml_dsa(
                    &key,
                    &HashMlDsaRequest {
                        parameter_set,
                        input: hash_input(hash, prehashed, &input),
                        context: &job.domain_context,
                        hedging: MlDsaHedging::Deterministic,
                    },
                    &signature,
                ),
                SignatureProfile::HashSlhDsa {
                    parameter_set,
                    hash,
                    prehashed,
                } => session.verify_hash_slh_dsa(
                    &key,
                    &HashSlhDsaRequest {
                        parameter_set,
                        input: hash_input(hash, prehashed, &input),
                        context: &job.domain_context,
                        hedging: SlhDsaHedging::Deterministic,
                    },
                    &signature,
                ),
            }
            .map_err(|error| match error {
                pkcs11_client::Error::SignatureMismatch => BackendError::SignatureMismatch,
                other => BackendError::from(&other),
            })
        })
    }

    pub(in crate::backend) fn crypto_options(
        &self,
        scope: CryptoScope,
        software_hashing: bool,
    ) -> Result<BackendResult, BackendError> {
        let (options, context) = match scope.mode {
            CryptoMode::Hkdf
            | CryptoMode::Derive
            | CryptoMode::Wrap
            | CryptoMode::Unwrap
            | CryptoMode::Encapsulate
            | CryptoMode::Decapsulate => {
                return self.key_options(scope);
            }
            CryptoMode::Encrypt | CryptoMode::Decrypt => return self.cipher_options(scope),
            CryptoMode::Sign => {
                let (index, uri, key) = self.signing_location(scope)?;
                let module = &self.modules[index];
                read_session(module, &uri, module.read_mode(scope.token)?, |session| {
                    signing_options(session, &key, software_hashing)
                })?
            }
            CryptoMode::Verify => {
                let (_, class) = self.reference(scope.module, scope.token, scope.object)?;
                if class == Some(ObjectClass::CERTIFICATE) {
                    (self.verification_certificate(scope)?.options(), false)
                } else {
                    (self.public_verification_options(scope)?, false)
                }
            }
        };
        Ok(BackendResult::CryptoOptions {
            scope,
            options,
            context,
        })
    }
    fn sign_file(&self, scope: CryptoScope, job: CryptoJob) -> Result<(), BackendError> {
        match job.parameters {
            SignatureProfile::MlDsa(parameter_set) => {
                MlDsaRequest {
                    parameter_set,
                    message: &[],
                    context: &job.domain_context,
                    hedging: MlDsaHedging::Required,
                }
                .validate()
                .map_err(|_| BackendError::MlDsaContext)?;
                if job.software_hashing {
                    return Err(BackendError::SignatureChoice);
                }
            }
            SignatureProfile::HashMlDsa { .. } => {
                if job.software_hashing {
                    return Err(BackendError::SignatureChoice);
                }
                if job.domain_context.len() > 255 {
                    return Err(BackendError::MlDsaContext);
                }
            }
            SignatureProfile::SlhDsa(_) | SignatureProfile::HashSlhDsa { .. } => {
                if job.software_hashing {
                    return Err(BackendError::SignatureChoice);
                }
                if job.domain_context.len() > 255 {
                    return Err(BackendError::PqcContext);
                }
            }
            SignatureProfile::EdDsa(_)
                if job.software_hashing || !job.domain_context.is_empty() =>
            {
                return Err(BackendError::SignatureChoice);
            }
            SignatureProfile::Classical(_) if !job.domain_context.is_empty() => {
                return Err(BackendError::SignatureChoice);
            }
            _ => {}
        }
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
        validate_hash_input(job.parameters, input.len())?;
        let signature = read_session(module, &uri, module.read_mode(scope.token)?, |session| {
            let (options, always_authenticate) =
                signing_options(session, &key, job.software_hashing)?;
            if !options
                .iter()
                .any(|choice| choice.parameters == job.parameters)
            {
                return Err(BackendError::SignatureChoice);
            }
            if always_authenticate && job.context.is_none() {
                return Err(BackendError::ContextRequired);
            }
            // Reserve the path only after validating choices, before signing.
            let output = management::create_output(&job.signature)?;
            let context = if always_authenticate {
                job.context.as_ref().map(|pin| match pin {
                    SecretInput::Value(pin) => Pin::Value(pin),
                    SecretInput::ProtectedPath => Pin::ProtectedPath,
                })
            } else {
                None
            };
            let signature = match job.parameters {
                SignatureProfile::Classical(parameters) => session.sign(
                    &key,
                    &parameters.request(SignInput::Message(&input)),
                    &policy(job.software_hashing),
                    context,
                ),
                SignatureProfile::MlDsa(parameter_set) => session.sign_ml_dsa(
                    &key,
                    &MlDsaRequest {
                        parameter_set,
                        message: &input,
                        context: &job.domain_context,
                        hedging: MlDsaHedging::Required,
                    },
                    &MlDsaSigningPolicy::default(),
                    context,
                ),
                SignatureProfile::EdDsa(curve) => session.sign_eddsa(
                    &key,
                    &EdDsaRequest {
                        curve,
                        message: &input,
                    },
                    context,
                ),
                SignatureProfile::SlhDsa(parameter_set) => session.sign_slh_dsa(
                    &key,
                    &SlhDsaRequest {
                        parameter_set,
                        message: &input,
                        context: &job.domain_context,
                        hedging: SlhDsaHedging::Required,
                    },
                    &SlhDsaSigningPolicy::default(),
                    context,
                ),
                SignatureProfile::HashSlhDsa {
                    parameter_set,
                    hash,
                    prehashed,
                } => session.sign_hash_slh_dsa(
                    &key,
                    &HashSlhDsaRequest {
                        parameter_set,
                        input: hash_input(hash, prehashed, &input),
                        context: &job.domain_context,
                        hedging: SlhDsaHedging::Required,
                    },
                    &HashSlhDsaSigningPolicy::default(),
                    context,
                ),
                SignatureProfile::HashMlDsa {
                    parameter_set,
                    hash,
                    prehashed,
                } => session.sign_hash_ml_dsa(
                    &key,
                    &HashMlDsaRequest {
                        parameter_set,
                        input: hash_input(hash, prehashed, &input),
                        context: &job.domain_context,
                        hedging: MlDsaHedging::Required,
                    },
                    &HashMlDsaSigningPolicy::default(),
                    context,
                ),
            }
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
    pub(in crate::backend) fn crypto(
        &mut self,
        scope: CryptoScope,
        job: CryptoJob,
    ) -> Result<BackendResult, BackendError> {
        if scope.mode == CryptoMode::Verify {
            let (_, class) = self.reference(scope.module, scope.token, scope.object)?;
            if class == Some(ObjectClass::CERTIFICATE) {
                self.verification_certificate(scope)?.verify(job)?;
            } else {
                self.verify_public_file(scope, job)?;
            }
            return Ok(BackendResult::Verified { scope });
        }
        if scope.mode != CryptoMode::Sign {
            return Err(BackendError::SignatureChoice);
        }
        let operation = self.sign_file(scope, job);
        Ok(self.finish_crypto(scope, operation))
    }
    pub(in crate::backend) fn finish_crypto(
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
