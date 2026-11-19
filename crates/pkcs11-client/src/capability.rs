// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, FunctionAvailability, MechanismCapability, Pkcs11Uri, Provider};

impl Provider {
    /// Snapshot token mechanisms with family, operations, bounds and whether a
    /// typed execution path exists.
    pub fn mechanism_capabilities(
        &self,
        uri: &Pkcs11Uri,
    ) -> Result<Vec<MechanismCapability>, Error> {
        Ok(self
            .module
            .resolve_token_uri(uri)?
            .mechanism_capabilities()?)
    }

    /// Report which standard functions the selected upstream interface provides.
    pub fn function_availability(&self) -> Result<Vec<FunctionAvailability>, Error> {
        Ok(self.module.function_availability()?)
    }
}
