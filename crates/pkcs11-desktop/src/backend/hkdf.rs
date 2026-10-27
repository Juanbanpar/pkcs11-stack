// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{BackendError, CryptoScope, KeyJob, Registry, browse::read_session};
use pkcs11_client::{HkdfCapabilities, HkdfMode, HkdfOutput, HkdfRequest, SessionMode};

pub struct HkdfJob {
    pub mode: HkdfMode,
    pub output: HkdfOutput,
    pub salt: Vec<u8>,
    pub salt_key: Option<pkcs11_client::ObjectRef>,
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
        if job.salt_key.is_some() {
            request.validate_with_salt_key(job.mode)
        } else {
            request.validate_for_mode(job.mode)
        }
        .map_err(|_| BackendError::HkdfInput)?;
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
                if let Some(salt_key) = &job.salt_key {
                    session.derive_hkdf_with_salt_key(&reference, salt_key, &request, job.mode)
                } else {
                    session.derive_hkdf_with_mode(&reference, &request, job.mode)
                }
                .map_err(|e| BackendError::from(&e))
            },
        )
    }
}

#[cfg(test)]
#[path = "hkdf_tests.rs"]
mod tests;
