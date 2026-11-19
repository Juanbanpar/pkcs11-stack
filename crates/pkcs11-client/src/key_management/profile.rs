// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, KeyOperation, KeyOperationProfile, ManagementSession, ObjectRef};

impl ManagementSession<'_> {
    /// Advisory profile after current key, permission and provider checks, with no mutation.
    pub fn key_operation_options(
        &mut self,
        key: &ObjectRef,
        operation: KeyOperation,
    ) -> Result<KeyOperationProfile, Error> {
        Ok(self.session.key_operation_profile(key, operation)?)
    }
}
