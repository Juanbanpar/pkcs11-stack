// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, ManagementSession, Pbkdf2Request};
impl ManagementSession<'_> {
    /// Inspect native PBKDF2 generation support. PRF/template support is advisory.
    pub fn pbkdf2_supported(&self) -> Result<bool, Error> {
        Ok(self.session.pbkdf2_supported()?)
    }
    /// Generate one private, sensitive, nonextractable token key from exact
    /// password/salt bytes. Requires RW access and a new ID. No fallback or retry;
    /// failures can leave persistent effects. Check closure before reporting success.
    pub fn generate_pbkdf2(&mut self, request: &Pbkdf2Request<'_>) -> Result<(), Error> {
        Ok(self.session.generate_pbkdf2(request)?)
    }
}
