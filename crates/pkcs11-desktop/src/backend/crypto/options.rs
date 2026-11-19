// SPDX-License-Identifier: MIT OR Apache-2.0
use pkcs11_client::{
    AttributeType, KeyType, ManagementSession, MlDsaSigningPolicy, PrehashAlgorithm, PrivateKeyRef,
    PublicKeyRef, SignatureAlgorithm, SignatureParameters,
};

use super::{BackendError, SignatureOption, SignatureProfile, policy};

pub(super) fn public_verification_options(
    session: &mut ManagementSession<'_>,
    key: &PublicKeyRef,
) -> Result<Vec<SignatureOption>, BackendError> {
    let reads = session
        .inspect(key.as_object_ref(), &[AttributeType::KeyType])
        .map_err(|e| BackendError::from(&e))?;
    let mut options = Vec::new();
    match super::super::browse::key_type(&reads) {
        Some(KeyType::RSA) => {
            for algorithm in [SignatureAlgorithm::RsaPkcs1, SignatureAlgorithm::RsaPss] {
                for digest in [
                    pkcs11_client::DigestAlgorithm::Sha256,
                    pkcs11_client::DigestAlgorithm::Sha384,
                    pkcs11_client::DigestAlgorithm::Sha512,
                ] {
                    options.push(SignatureOption {
                        parameters: SignatureProfile::Classical(SignatureParameters {
                            algorithm,
                            digest,
                            pss: (algorithm == SignatureAlgorithm::RsaPss).then_some(
                                pkcs11_client::PssParameters {
                                    mgf_digest: digest,
                                    salt_len: digest.output_len(),
                                },
                            ),
                        }),
                        plan: None,
                    });
                }
            }
        }
        Some(KeyType::EC) => {
            for digest in [
                pkcs11_client::DigestAlgorithm::Sha256,
                pkcs11_client::DigestAlgorithm::Sha384,
                pkcs11_client::DigestAlgorithm::Sha512,
            ] {
                options.push(SignatureOption {
                    parameters: SignatureProfile::Classical(SignatureParameters {
                        algorithm: SignatureAlgorithm::Ecdsa,
                        digest,
                        pss: None,
                    }),
                    plan: None,
                });
            }
        }
        Some(KeyType::ML_DSA) => {
            let parameter_set = session
                .ml_dsa_public_parameter_set(key)
                .map_err(|e| BackendError::from(&e))?;
            options.push(SignatureOption {
                parameters: SignatureProfile::MlDsa(parameter_set),
                plan: None,
            });
            for hash in [
                PrehashAlgorithm::Sha256,
                PrehashAlgorithm::Sha384,
                PrehashAlgorithm::Sha512,
            ] {
                for prehashed in [false, true] {
                    options.push(SignatureOption {
                        parameters: SignatureProfile::HashMlDsa {
                            parameter_set,
                            hash,
                            prehashed,
                        },
                        plan: None,
                    });
                }
            }
        }
        Some(KeyType::SLH_DSA) => {
            let parameter_set = session
                .slh_dsa_public_parameter_set(key)
                .map_err(|e| BackendError::from(&e))?;
            options.push(SignatureOption {
                parameters: SignatureProfile::SlhDsa(parameter_set),
                plan: None,
            });
            for hash in [
                PrehashAlgorithm::Sha256,
                PrehashAlgorithm::Sha384,
                PrehashAlgorithm::Sha512,
            ] {
                for prehashed in [false, true] {
                    options.push(SignatureOption {
                        parameters: SignatureProfile::HashSlhDsa {
                            parameter_set,
                            hash,
                            prehashed,
                        },
                        plan: None,
                    });
                }
            }
        }
        Some(KeyType::EC_EDWARDS) => {
            let curve = session
                .eddsa_public_curve(key)
                .map_err(|e| BackendError::from(&e))?;
            options.push(SignatureOption {
                parameters: SignatureProfile::EdDsa(curve),
                plan: None,
            });
        }
        _ => return Err(BackendError::SigningUnavailable),
    }
    Ok(options)
}

pub(super) fn signing_options(
    session: &mut ManagementSession<'_>,
    key: &PrivateKeyRef,
    software: bool,
) -> Result<(Vec<SignatureOption>, bool), BackendError> {
    let reads = session
        .inspect(key.as_object_ref(), &[AttributeType::KeyType])
        .map_err(|e| BackendError::from(&e))?;
    match super::super::browse::key_type(&reads) {
        Some(KeyType::ML_DSA) => {
            if software {
                return Err(BackendError::SignatureChoice);
            }
            let caps = session
                .ml_dsa_capabilities(key)
                .map_err(|e| BackendError::from(&e))?;
            let mut options = Vec::new();
            let mut always_authenticate = caps.always_authenticate;
            if caps.can_sign
                && MlDsaSigningPolicy::default()
                    .parameter_sets
                    .contains(&caps.parameter_set)
            {
                options.push(SignatureOption {
                    parameters: SignatureProfile::MlDsa(caps.parameter_set),
                    plan: None,
                });
            }
            for hash in [
                PrehashAlgorithm::Sha256,
                PrehashAlgorithm::Sha384,
                PrehashAlgorithm::Sha512,
            ] {
                for prehashed in [false, true] {
                    let caps = session
                        .hash_ml_dsa_capabilities(key, hash, prehashed)
                        .map_err(|e| BackendError::from(&e))?;
                    if caps.can_sign {
                        always_authenticate |= caps.always_authenticate;
                        options.push(SignatureOption {
                            parameters: SignatureProfile::HashMlDsa {
                                parameter_set: caps.parameter_set,
                                hash,
                                prehashed,
                            },
                            plan: None,
                        });
                    }
                }
            }
            if options.is_empty() {
                return Err(BackendError::SigningUnavailable);
            }
            Ok((options, always_authenticate))
        }
        Some(KeyType::SLH_DSA) => {
            if software {
                return Err(BackendError::SignatureChoice);
            }
            let caps = session
                .slh_dsa_capabilities(key)
                .map_err(|e| BackendError::from(&e))?;
            let mut options = Vec::new();
            let mut always_authenticate = caps.always_authenticate;
            if caps.can_sign {
                options.push(SignatureOption {
                    parameters: SignatureProfile::SlhDsa(caps.parameter_set),
                    plan: None,
                });
            }
            for hash in [
                PrehashAlgorithm::Sha256,
                PrehashAlgorithm::Sha384,
                PrehashAlgorithm::Sha512,
            ] {
                for prehashed in [false, true] {
                    let caps = session
                        .hash_slh_dsa_capabilities(key, hash, prehashed)
                        .map_err(|e| BackendError::from(&e))?;
                    if caps.can_sign {
                        always_authenticate |= caps.always_authenticate;
                        options.push(SignatureOption {
                            parameters: SignatureProfile::HashSlhDsa {
                                parameter_set: caps.parameter_set,
                                hash,
                                prehashed,
                            },
                            plan: None,
                        });
                    }
                }
            }
            if options.is_empty() {
                return Err(BackendError::SigningUnavailable);
            }
            Ok((options, always_authenticate))
        }
        Some(KeyType::EC_EDWARDS) => {
            if software {
                return Err(BackendError::SignatureChoice);
            }
            let caps = session
                .eddsa_capabilities(key)
                .map_err(|e| BackendError::from(&e))?;
            if !caps.can_sign {
                return Err(BackendError::SigningUnavailable);
            }
            Ok((
                vec![SignatureOption {
                    parameters: SignatureProfile::EdDsa(caps.curve),
                    plan: None,
                }],
                caps.always_authenticate,
            ))
        }
        Some(KeyType::RSA | KeyType::EC) => {
            let options = session
                .signing_options(key, &policy(software))
                .map_err(|e| BackendError::from(&e))?;
            Ok((
                options
                    .choices
                    .into_iter()
                    .map(|choice| SignatureOption {
                        parameters: SignatureProfile::Classical(choice.parameters),
                        plan: Some((choice.mechanism, choice.hashing)),
                    })
                    .collect(),
                options.always_authenticate,
            ))
        }
        _ => Err(BackendError::SigningUnavailable),
    }
}
