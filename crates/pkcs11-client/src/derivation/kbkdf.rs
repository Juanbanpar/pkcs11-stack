// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Error, KbkdfCapabilities, KbkdfMode, KbkdfPrf, KbkdfRequest, ManagementSession, ObjectRef,
};

impl ManagementSession<'_> {
    /// Inspect supported SP 800-108 PRF/mode combinations for a base key.
    pub fn kbkdf_options(&mut self, base: &ObjectRef) -> Result<Vec<KbkdfCapabilities>, Error> {
        Ok(self.session.kbkdf_options(base)?)
    }

    /// Derive one persistent key with SP 800-108.
    pub fn derive_kbkdf(
        &mut self,
        base: &ObjectRef,
        request: &KbkdfRequest<'_>,
        mode: KbkdfMode,
        iv: &[u8],
    ) -> Result<(), Error> {
        Ok(self.session.derive_kbkdf(base, request, mode, iv)?)
    }

    /// Inspect one explicit SP 800-108 PRF and mode.
    pub fn kbkdf_capabilities(
        &mut self,
        base: &ObjectRef,
        prf: KbkdfPrf,
        mode: KbkdfMode,
    ) -> Result<KbkdfCapabilities, Error> {
        Ok(self.session.kbkdf_capabilities(base, prf, mode)?)
    }
}
