// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{BackendError, CryptoScope, KeyJob, Registry, browse::read_session};
use pkcs11_client::{HkdfCapabilities, HkdfOutput, HkdfRequest, SessionMode};

pub struct HkdfJob {
    pub output: HkdfOutput,
    pub salt: Vec<u8>,
    pub info: Vec<u8>,
    pub id: Vec<u8>,
    pub label: Vec<u8>,
}
impl Registry {
    pub(super) fn hkdf_action(
        &self,
        scope: CryptoScope,
        profile: HkdfCapabilities,
        job: KeyJob,
    ) -> Result<(), BackendError> {
        let KeyJob::Hkdf(job) = job else {
            return Err(BackendError::KeyOperationUnavailable);
        };
        let request = HkdfRequest {
            digest: profile.digest,
            salt: &job.salt,
            info: &job.info,
            output: job.output,
            id: &job.id,
            label: &job.label,
        };
        request.validate().map_err(|_| BackendError::HkdfInput)?;
        let (index, uri, reference) = self.key_location(scope)?;
        read_session(
            &self.modules[index],
            &uri,
            SessionMode::ReadWrite,
            |session| {
                if session
                    .hkdf_capabilities(&reference, profile.digest)
                    .map_err(|e| BackendError::from(&e))?
                    != profile
                {
                    return Err(BackendError::KeyOperationUnavailable);
                }
                session
                    .derive_hkdf(&reference, &request)
                    .map_err(|e| BackendError::from(&e))
            },
        )
    }
}

#[cfg(test)]
#[path = "hkdf_tests.rs"]
mod tests;
