// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{BackendError, CryptoMode, CryptoScope, KeyJob, Registry, browse::read_session};
use pkcs11_client::{AES_CMAC_MAXIMUM_MESSAGE, AesCmacOptions, MacOperation};
use std::io::Write;
pub(super) fn operation(mode: CryptoMode) -> Result<MacOperation, BackendError> {
    match mode {
        CryptoMode::Mac => Ok(MacOperation::Generate),
        CryptoMode::VerifyMac => Ok(MacOperation::Verify),
        _ => Err(BackendError::KeyOperationUnavailable),
    }
}
impl Registry {
    pub(super) fn cmac_action(
        &self,
        scope: CryptoScope,
        profile: AesCmacOptions,
        job: KeyJob,
    ) -> Result<(), BackendError> {
        let KeyJob::Cmac {
            input,
            tag,
            profile: tag_profile,
        } = job
        else {
            return Err(BackendError::KeyOperationUnavailable);
        };
        let operation = operation(scope.mode)?;
        if !profile.supports(tag_profile) {
            return Err(BackendError::KeyOperationUnavailable);
        }
        let tag_length = tag_profile.tag_length();
        let message = super::key_operations::read(&input, AES_CMAC_MAXIMUM_MESSAGE as u64)
            .map_err(|_| BackendError::MacInput)?;
        let expected = if operation == MacOperation::Verify {
            let tag = super::key_operations::read(&tag, tag_length as u64)
                .map_err(|_| BackendError::MacInput)?;
            if tag.len() != tag_length {
                return Err(BackendError::MacInput);
            }
            Some(tag)
        } else {
            None
        };
        let (index, uri, reference) = self.key_location(scope)?;
        let module = &self.modules[index];
        let result = read_session(module, &uri, module.read_mode(scope.token)?, |session| {
            if session
                .aes_cmac_options(&reference, operation)
                .map_err(|e| BackendError::from(&e))?
                != profile
            {
                return Err(BackendError::KeyOperationUnavailable);
            }
            if let Some(expected) = expected {
                session
                    .verify_aes_cmac_with_profile(&reference, &message, &expected, tag_profile)
                    .map_err(|error| match error {
                        pkcs11_client::Error::MacMismatch => BackendError::MacMismatch,
                        other => BackendError::from(&other),
                    })?;
                Ok(None)
            } else {
                let output = super::management::create_output(&tag)?;
                let value = session
                    .mac_aes_cmac_with_profile(&reference, &message, tag_profile)
                    .map_err(|e| BackendError::from(&e))?;
                Ok(Some((output, value)))
            }
        })?;
        if let Some((mut output, value)) = result {
            output
                .write_all(&value)
                .and_then(|()| output.flush())
                .map_err(|_| BackendError::FileWrite)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "cmac_tests.rs"]
mod tests;
