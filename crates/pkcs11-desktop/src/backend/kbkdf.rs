// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{BackendError, CryptoMode, CryptoScope, KeyJob, Registry, browse::read_session};
use pkcs11_client::{DigestAlgorithm, KbkdfCapabilities, KbkdfOutput, KbkdfRequest, SessionMode};
pub struct KbkdfJob {
    pub digest: DigestAlgorithm,
    pub output: KbkdfOutput,
    pub kdf_label: Vec<u8>,
    pub context: Vec<u8>,
    pub id: Vec<u8>,
    pub label: Vec<u8>,
}
impl Registry {
    pub(super) fn kbkdf_action(
        &self,
        scope: CryptoScope,
        profile: KbkdfCapabilities,
        job: KeyJob,
    ) -> Result<(), BackendError> {
        let KeyJob::Kbkdf(job) = job else {
            return Err(BackendError::KeyOperationUnavailable);
        };
        if scope.mode != CryptoMode::Kbkdf || !profile.supports(job.digest) {
            return Err(BackendError::KeyOperationUnavailable);
        }
        let request = KbkdfRequest {
            digest: job.digest,
            output: job.output,
            kdf_label: &job.kdf_label,
            context: &job.context,
            id: &job.id,
            label: &job.label,
        };
        request.validate().map_err(|_| BackendError::KbkdfInput)?;
        let (index, uri, reference) = self.key_location(scope)?;
        read_session(
            &self.modules[index],
            &uri,
            SessionMode::ReadWrite,
            |session| {
                if session
                    .kbkdf_capabilities(&reference)
                    .map_err(|e| BackendError::from(&e))?
                    != profile
                {
                    return Err(BackendError::KeyOperationUnavailable);
                }
                session
                    .derive_kbkdf(&reference, &request)
                    .map_err(|e| BackendError::from(&e))
            },
        )
    }
}
#[cfg(test)]
#[path = "kbkdf_tests.rs"]
mod tests;
