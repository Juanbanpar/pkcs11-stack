// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{BackendError, CryptoMode, CryptoScope, KeyJob, Registry, browse::read_session};
use pkcs11_client::{
    MlKemOperation, MlKemParameterSet, MlKemRequest, PrivateKeyRef, PublicKeyRef, SessionMode,
};
use std::io::Write;

pub(super) fn operation(mode: CryptoMode) -> Result<MlKemOperation, BackendError> {
    match mode {
        CryptoMode::Encapsulate => Ok(MlKemOperation::Encapsulate),
        CryptoMode::Decapsulate => Ok(MlKemOperation::Decapsulate),
        _ => Err(BackendError::KeyOperationUnavailable),
    }
}
impl Registry {
    pub(super) fn kem_action(
        &self,
        scope: CryptoScope,
        parameter: MlKemParameterSet,
        job: KeyJob,
    ) -> Result<(), BackendError> {
        let direction = operation(scope.mode)?;
        let (index, uri, reference) = self.key_location(scope)?;
        let module = &self.modules[index];
        match (direction, job) {
            (MlKemOperation::Encapsulate, KeyJob::Encapsulate { output, id, label }) => {
                let request = MlKemRequest {
                    parameter_set: parameter,
                    id: &id,
                    label: &label,
                };
                request
                    .validate()
                    .map_err(|_| BackendError::KeyOperationInput)?;
                let key = PublicKeyRef::new(
                    reference
                        .uri()
                        .to_string()
                        .parse()
                        .map_err(|_| BackendError::KeyOperationUnavailable)?,
                )
                .map_err(|_| BackendError::KeyOperationUnavailable)?;
                // Reserve the output before creating a token secret. Release ciphertext only
                // after the operation and checked session closure both succeed.
                let (mut output, ciphertext) =
                    read_session(module, &uri, SessionMode::ReadWrite, |session| {
                        if session
                            .ml_kem_capabilities(&reference, direction)
                            .map_err(|e| BackendError::from(&e))?
                            .parameter_set
                            != parameter
                        {
                            return Err(BackendError::KeyOperationUnavailable);
                        }
                        let output = super::management::create_output(&output)?;
                        let ciphertext = session
                            .encapsulate_ml_kem(&key, &request)
                            .map_err(|e| BackendError::from(&e))?;
                        Ok((output, ciphertext))
                    })?;
                output
                    .write_all(&ciphertext)
                    .and_then(|()| output.flush())
                    .map_err(|_| BackendError::FileWrite)
            }
            (MlKemOperation::Decapsulate, KeyJob::Decapsulate { input, id, label }) => {
                let request = MlKemRequest {
                    parameter_set: parameter,
                    id: &id,
                    label: &label,
                };
                request
                    .validate()
                    .map_err(|_| BackendError::KeyOperationInput)?;
                let ciphertext =
                    super::key_operations::read(&input, parameter.ciphertext_length() as u64)?;
                if ciphertext.len() != parameter.ciphertext_length() {
                    return Err(BackendError::KeyOperationInput);
                }
                let key = PrivateKeyRef::new(
                    reference
                        .uri()
                        .to_string()
                        .parse()
                        .map_err(|_| BackendError::KeyOperationUnavailable)?,
                )
                .map_err(|_| BackendError::KeyOperationUnavailable)?;
                read_session(module, &uri, SessionMode::ReadWrite, |session| {
                    if session
                        .ml_kem_capabilities(&reference, direction)
                        .map_err(|e| BackendError::from(&e))?
                        .parameter_set
                        != parameter
                    {
                        return Err(BackendError::KeyOperationUnavailable);
                    }
                    session
                        .decapsulate_ml_kem(&key, &request, &ciphertext)
                        .map_err(|e| BackendError::from(&e))
                })
            }
            _ => Err(BackendError::KeyOperationUnavailable),
        }
    }
}

#[cfg(test)]
#[path = "kem_tests.rs"]
mod tests;
