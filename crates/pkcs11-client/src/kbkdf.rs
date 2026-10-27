// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, KbkdfCapabilities, KbkdfRequest, ManagementSession, ObjectRef};
impl ManagementSession<'_> {
    /// Inspect native SP 800-108 counter-mode support for one generic/SHA-2 HMAC
    /// secret. Requires sensitivity, nonextractability and derivation permission.
    /// This reads metadata only; individual PRF/template support remains advisory.
    pub fn kbkdf_capabilities(&mut self, base: &ObjectRef) -> Result<KbkdfCapabilities, Error> {
        Ok(self.session.kbkdf_capabilities(base)?)
    }
    /// Apply the explicit counter-mode profile once with HMAC-SHA-256/384/512,
    /// a big-endian 32-bit counter, zero separator and 32-bit output length in bits.
    /// Creates one persistent private, sensitive, nonextractable key. RW mode and
    /// a new ID are required. No values leave the token, no retry or rollback;
    /// failed calls may leave effects. Check session closure before reporting success.
    pub fn derive_kbkdf(
        &mut self,
        base: &ObjectRef,
        request: &KbkdfRequest<'_>,
    ) -> Result<(), Error> {
        Ok(self.session.derive_kbkdf(base, request)?)
    }
}
