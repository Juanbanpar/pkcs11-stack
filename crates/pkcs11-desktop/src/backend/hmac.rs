// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{BackendError, CryptoMode, CryptoScope, KeyJob, Registry, browse::read_session};
use pkcs11_client::{HMAC_MAXIMUM_MESSAGE, HmacOptions, MacOperation};
use std::io::Write;
pub(super) fn operation(mode: CryptoMode) -> Result<MacOperation, BackendError> {
    match mode {
        CryptoMode::Hmac => Ok(MacOperation::Generate),
        CryptoMode::VerifyHmac => Ok(MacOperation::Verify),
        _ => Err(BackendError::KeyOperationUnavailable),
    }
}
impl Registry {
    pub(super) fn hmac_action(
        &self,
        scope: CryptoScope,
        options: HmacOptions,
        job: KeyJob,
    ) -> Result<(), BackendError> {
        let KeyJob::Hmac {
            algorithm,
            profile,
            input,
            tag,
        } = job
        else {
            return Err(BackendError::KeyOperationUnavailable);
        };
        if !options.supports(algorithm, profile) {
            return Err(BackendError::KeyOperationUnavailable);
        }
        let direction = operation(scope.mode)?;
        let message = super::key_operations::read(&input, HMAC_MAXIMUM_MESSAGE as u64)
            .map_err(|_| BackendError::MacInput)?;
        let expected = if direction == MacOperation::Verify {
            let value = super::key_operations::read(&tag, profile.tag_length(algorithm) as u64)
                .map_err(|_| BackendError::MacInput)?;
            if value.len() != profile.tag_length(algorithm) {
                return Err(BackendError::MacInput);
            }
            Some(value)
        } else {
            None
        };
        let (index, uri, reference) = self.key_location(scope)?;
        let module = &self.modules[index];
        let result = read_session(module, &uri, module.read_mode(scope.token)?, |session| {
            if session
                .hmac_options(&reference, direction)
                .map_err(|e| BackendError::from(&e))?
                != options
            {
                return Err(BackendError::KeyOperationUnavailable);
            }
            if let Some(expected) = expected {
                session
                    .verify_hmac_with_profile(&reference, algorithm, &message, &expected, profile)
                    .map_err(|error| match error {
                        pkcs11_client::Error::MacMismatch => BackendError::MacMismatch,
                        other => BackendError::from(&other),
                    })?;
                Ok(None)
            } else {
                let output = super::management::create_output(&tag)?;
                let value = session
                    .mac_hmac_with_profile(&reference, algorithm, &message, profile)
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
#[path = "hmac_tests.rs"]
mod tests;
