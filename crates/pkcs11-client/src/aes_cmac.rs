// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AES_CMAC_TAG_LENGTH, AesCmacCapabilities, Error, MacOperation, ManagementSession, ObjectRef,
};
impl ManagementSession<'_> {
    /// Inspect native full-tag AES-CMAC support and current AES key permissions.
    /// Does not read key values or create a tag; advertised support is advisory.
    pub fn aes_cmac_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: MacOperation,
    ) -> Result<AesCmacCapabilities, Error> {
        Ok(self.session.aes_cmac_capabilities(key, operation)?)
    }
    /// Generate a full 16-byte native AES-CMAC for a message up to 16 MiB.
    /// The sensitive, nonextractable AES key must permit signing. Empty messages
    /// and RO sessions are allowed; no software fallback or truncation occurs.
    /// Native failures invalidate the session; check closure before releasing output.
    pub fn mac_aes_cmac(
        &mut self,
        key: &ObjectRef,
        message: &[u8],
    ) -> Result<[u8; AES_CMAC_TAG_LENGTH], Error> {
        Ok(self.session.mac_aes_cmac(key, message)?)
    }
    /// Verify the exact message and full tag using native verification permission.
    /// Returns MacMismatch for incorrect tag length or contents. That result leaves
    /// the session reusable; other native failures invalidate it. Check closure.
    pub fn verify_aes_cmac(
        &mut self,
        key: &ObjectRef,
        message: &[u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        match self.session.verify_aes_cmac(key, message, tag) {
            Err(pkcs11_runtime::Error::MacMismatch) => Err(Error::MacMismatch),
            result => Ok(result?),
        }
    }
}
