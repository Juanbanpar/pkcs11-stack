// SPDX-License-Identifier: MIT OR Apache-2.0
use pkcs11_client::{
    Certificate, EdDsaCertificate, EdDsaRequest, MlDsaCertificate, MlDsaHedging, MlDsaRequest,
    SignInput,
};

use super::super::BackendError;

use super::{CryptoJob, SignatureOption, SignatureProfile, operations::read_bounded};

pub(super) enum VerificationCertificate {
    Classical(Certificate),
    MlDsa(MlDsaCertificate),
    EdDsa(EdDsaCertificate),
}
impl VerificationCertificate {
    pub(super) fn from_der(der: Vec<u8>) -> Result<Self, BackendError> {
        match Certificate::from_der(der.clone()) {
            Ok(certificate) => Ok(Self::Classical(certificate)),
            // Only an unsupported key algorithm permits trying another parser.
            // Malformed certificates retain their original error.
            Err(pkcs11_client::Error::UnsupportedCertificateKey) => {
                match MlDsaCertificate::from_der(der.clone()) {
                    Ok(certificate) => Ok(Self::MlDsa(certificate)),
                    Err(pkcs11_client::Error::UnsupportedCertificateKey) => {
                        EdDsaCertificate::from_der(der)
                            .map(Self::EdDsa)
                            .map_err(|e| BackendError::from(&e))
                    }
                    Err(error) => Err(BackendError::from(&error)),
                }
            }
            Err(error) => Err(BackendError::from(&error)),
        }
    }
    pub(super) fn options(&self) -> Vec<SignatureOption> {
        let parameters = match self {
            Self::Classical(certificate) => certificate
                .verification_options()
                .into_iter()
                .map(SignatureProfile::Classical)
                .collect(),
            Self::MlDsa(certificate) => vec![SignatureProfile::MlDsa(certificate.parameter_set())],
            Self::EdDsa(certificate) => vec![SignatureProfile::EdDsa(certificate.curve())],
        };
        parameters
            .into_iter()
            .map(|parameters| SignatureOption {
                parameters,
                plan: None,
            })
            .collect()
    }
    pub(super) fn verify(&self, job: CryptoJob) -> Result<(), BackendError> {
        if job.context.is_some()
            || !self
                .options()
                .iter()
                .any(|option| option.parameters == job.parameters)
        {
            return Err(BackendError::SignatureChoice);
        }
        match job.parameters {
            SignatureProfile::MlDsa(_) if job.software_hashing => {
                return Err(BackendError::SignatureChoice);
            }
            SignatureProfile::MlDsa(_) if job.domain_context.len() > 255 => {
                return Err(BackendError::MlDsaContext);
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
        let input = read_bounded(&job.input, 16 * 1024 * 1024)?;
        let signature = read_bounded(&job.signature, 64 * 1024)?;
        let result = match (self, job.parameters) {
            (Self::Classical(certificate), SignatureProfile::Classical(parameters)) => certificate
                .verify_signature(&parameters.request(SignInput::Message(&input)), &signature),
            (Self::MlDsa(certificate), SignatureProfile::MlDsa(parameter_set)) => certificate
                .verify_signature(
                    &MlDsaRequest {
                        parameter_set,
                        message: &input,
                        context: &job.domain_context,
                        hedging: MlDsaHedging::Preferred,
                    },
                    &signature,
                ),
            (Self::EdDsa(certificate), SignatureProfile::EdDsa(curve)) => certificate
                .verify_signature(
                    &EdDsaRequest {
                        curve,
                        message: &input,
                    },
                    &signature,
                ),
            _ => return Err(BackendError::SignatureChoice),
        };
        result.map_err(|error| match error {
            pkcs11_client::Error::SignatureMismatch => BackendError::SignatureMismatch,
            other => BackendError::from(&other),
        })
    }
}
