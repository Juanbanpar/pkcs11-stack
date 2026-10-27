// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Error, HmacAlgorithm, HmacCapabilities, HmacKeyRequest, HmacOptions, HmacTagProfile,
    MacOperation, ManagementSession, ObjectRef,
};
impl ManagementSession<'_> {
    /// Inspect permitted native general-tag algorithms for one MAC direction.
    pub fn hmac_general_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: MacOperation,
    ) -> Result<HmacCapabilities, Error> {
        Ok(self.session.hmac_general_capabilities(key, operation)?)
    }

    /// Inspect full and general HMAC permissions independently, without cryptography.
    pub fn hmac_options(
        &mut self,
        key: &ObjectRef,
        operation: MacOperation,
    ) -> Result<HmacOptions, Error> {
        Ok(self.session.hmac_options(key, operation)?)
    }
    /// Generate an explicitly selected native tag, bounded to half the hash output
    /// through its full length. No software truncation or fallback; check closure.
    pub fn mac_hmac_with_profile(
        &mut self,
        key: &ObjectRef,
        algorithm: HmacAlgorithm,
        message: &[u8],
        profile: HmacTagProfile,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .session
            .mac_hmac_with_profile(key, algorithm, message, profile)?)
    }
    /// Verify an exact agreed tag with the selected native full/general mechanism.
    /// MacMismatch leaves the session reusable; other native failures invalidate it.
    pub fn verify_hmac_with_profile(
        &mut self,
        key: &ObjectRef,
        algorithm: HmacAlgorithm,
        message: &[u8],
        tag: &[u8],
        profile: HmacTagProfile,
    ) -> Result<(), Error> {
        match self
            .session
            .verify_hmac_with_profile(key, algorithm, message, tag, profile)
        {
            Err(pkcs11_runtime::Error::MacMismatch) => Err(Error::MacMismatch),
            result => Ok(result?),
        }
    }
    /// Generate a persistent authentication secret restricted to the general HMAC
    /// mechanism. Callers agree on one length per key; the token does not encode it.
    /// RW mode is required; failure may leave effects. Check closure.
    pub fn generate_hmac_general_key(&mut self, request: &HmacKeyRequest<'_>) -> Result<(), Error> {
        self.session.generate_hmac_general_key(request)?;
        Ok(())
    }

    /// Inspect native full-tag HMAC profiles and direction-specific permissions.
    /// Requires a sensitive, nonextractable generic or matching HMAC secret.
    pub fn hmac_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: MacOperation,
    ) -> Result<HmacCapabilities, Error> {
        Ok(self.session.hmac_capabilities(key, operation)?)
    }
    /// Generate a full native HMAC for up to 16 MiB, including empty messages.
    /// No key values, software fallback or truncation. Native failures invalidate
    /// the session; check closure before releasing output. RO sessions are allowed.
    pub fn mac_hmac(
        &mut self,
        key: &ObjectRef,
        algorithm: HmacAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.mac_hmac(key, algorithm, message)?)
    }
    /// Verify the exact message and full tag natively. Wrong length or contents
    /// return MacMismatch and leave the session reusable. Other native failures
    /// invalidate it; check closure. Verification permission is checked separately.
    pub fn verify_hmac(
        &mut self,
        key: &ObjectRef,
        algorithm: HmacAlgorithm,
        message: &[u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        match self.session.verify_hmac(key, algorithm, message, tag) {
            Err(pkcs11_runtime::Error::MacMismatch) => Err(Error::MacMismatch),
            result => Ok(result?),
        }
    }
    /// Generate a persistent, private, nonextractable hash-length generic secret
    /// restricted to the selected HMAC mechanism. Requires RW mode. Duplicate IDs
    /// are rejected; failure may leave effects without rollback. Check closure.
    pub fn generate_hmac_key(&mut self, request: &HmacKeyRequest<'_>) -> Result<(), Error> {
        self.session.generate_hmac_key(request)?;
        Ok(())
    }
}
