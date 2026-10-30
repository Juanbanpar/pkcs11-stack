// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Error, KbkdfCapabilities, KbkdfMode, KbkdfOptions, KbkdfRequest, ManagementSession, ObjectRef,
};
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
    /// Inspect a selected key for an explicit counter, feedback or double-pipeline profile.
    pub fn kbkdf_capabilities_with_mode(
        &mut self,
        base: &ObjectRef,
        mode: KbkdfMode,
    ) -> Result<KbkdfCapabilities, Error> {
        Ok(self.session.kbkdf_capabilities_with_mode(base, mode)?)
    }
    /// Inspect all three modes, omitting unsupported profiles while preserving
    /// selection/provider failures. No key values are read.
    pub fn kbkdf_options(&mut self, base: &ObjectRef) -> Result<KbkdfOptions, Error> {
        Ok(self.session.kbkdf_options(base)?)
    }
    /// Derive using an explicit mode. Feedback takes an optional public IV:
    /// empty or exactly 32/48/64 bytes matching the hash. Counter and double
    /// pipeline reject external IVs.
    /// Double pipeline initializes `A(0) = label || 0x00 || context || [L]_32`
    /// and uses A(i) followed by the counter in each output PRF input.
    /// The counter and output bit length are 32-bit big-endian, with a zero
    /// separator and one output key. Same permissions and cleanup contract as
    /// derive_kbkdf; no mode substitution, retry or software fallback.
    pub fn derive_kbkdf_with_mode(
        &mut self,
        base: &ObjectRef,
        request: &KbkdfRequest<'_>,
        mode: KbkdfMode,
        iv: &[u8],
    ) -> Result<(), Error> {
        Ok(self
            .session
            .derive_kbkdf_with_mode(base, request, mode, iv)?)
    }
}
