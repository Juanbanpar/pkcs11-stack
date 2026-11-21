// SPDX-License-Identifier: MIT OR Apache-2.0
use cryptoki::error::RvError;
use pkcs11_locator::{Pkcs11Uri, ResourceIdentity, TokenIdentity, TokenSelector};

use crate::{
    Error, MechanismInfo, MechanismType, Session, SessionMode, Slot, TokenInfo,
    error::{backend, unique},
};

use super::library::{Module, ModuleRef};

impl Module {
    /// Inspect a token in an explicitly selected current slot.
    pub fn token(&self, slot: Slot) -> Result<Token<'_>, Error> {
        let info = self
            .raw()?
            .get_token_info(slot)
            .map_err(|e| backend("token info", e))?;
        Ok(Token {
            module: ModuleRef::Borrowed(self),
            slot,
            info,
        })
    }
    /// Enumerate tokens, including uninitialized tokens when the module reports them.
    pub fn tokens(&self) -> Result<Vec<Token<'_>>, Error> {
        let mut tokens = Vec::new();
        for slot in self.slots(true)? {
            match self.token(slot) {
                Ok(token) => tokens.push(token),
                // A token may disappear between slot enumeration and inspection.
                Err(Error::Backend {
                    source: cryptoki::error::Error::Pkcs11(RvError::TokenNotPresent, _),
                    ..
                }) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(tokens)
    }
    /// Resolve token-only criteria within this module, rejecting zero/multiple matches.
    ///
    /// This intentionally takes the locator's partial TokenSelector. Module and
    /// object constraints are not part of token-only resolution.
    pub fn resolve_token(&self, selector: TokenSelector<'_>) -> Result<Token<'_>, Error> {
        let tokens = self
            .tokens()?
            .into_iter()
            .filter(|t| selector.matches(&t.identity()))
            .collect();
        unique(tokens, "token")
    }
    /// Resolve a token URI, enforcing module, slot and token constraints together.
    ///
    /// Object criteria, PIN queries, unknown path constraints and query attributes
    /// other than module-path are rejected. No library is loaded from the URI.
    /// Slot IDs select this module instance only; returned tokens retain metadata
    /// identity for subsequent operations. Empty criteria still require uniqueness.
    pub fn resolve_token_uri(&self, uri: &Pkcs11Uri) -> Result<Token<'_>, Error> {
        validate_token_uri(uri)?;
        let mut matches = Vec::new();
        for token in self.tokens()? {
            if token.matches_location(uri)? {
                matches.push(token);
            }
        }
        unique(matches, "token")
    }
}

/// Discovered token with stable metadata, bound to its owning [`Module`].
///
/// Use [`Self::open_session`] for an exclusive [`Session`] or pass this token
/// to [`crate::SessionPool::new`] for pooled access. Operations can return
/// [`Error::TokenChanged`] after the selected token's metadata changes.
#[derive(Debug)]
pub struct Token<'m> {
    pub(crate) module: ModuleRef<'m>,
    pub(crate) slot: Slot,
    pub(crate) info: TokenInfo,
}
impl<'m> Token<'m> {
    /// Current diagnostic slot ID; do not persist as token identity.
    pub fn slot(&self) -> Slot {
        self.slot
    }
    /// Metadata and token capability flags captured during discovery.
    pub fn info(&self) -> &TokenInfo {
        &self.info
    }
    /// Stable locator-compatible token metadata, independent of session state.
    pub fn identity(&self) -> TokenIdentity<'_> {
        token_identity(&self.info)
    }
    /// List mechanism identifiers advertised by this token.
    pub fn mechanisms(&self) -> Result<Vec<MechanismType>, Error> {
        self.validate()?;
        self.module
            .raw()?
            .get_mechanism_list(self.slot)
            .map_err(|e| backend("list mechanisms", e))
    }
    /// Inspect mechanism flags and key-size bounds without planning algorithms.
    pub fn mechanism_info(&self, mechanism: MechanismType) -> Result<MechanismInfo, Error> {
        self.validate()?;
        self.module
            .raw()?
            .get_mechanism_info(self.slot, mechanism)
            .map_err(|e| backend("mechanism info", e))
    }
    /// Open a non-pooled session, verifying token metadata before and after opening.
    pub fn open_session(&self, mode: SessionMode) -> Result<Session<'m>, Error> {
        Session::open(self, mode)
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let current = self
            .module
            .raw()?
            .get_token_info(self.slot)
            .map_err(|e| backend("validate token", e))?;
        if same_token(&self.info, &current) {
            Ok(())
        } else {
            Err(Error::TokenChanged)
        }
    }
    fn resource_identity(&self) -> ResourceIdentity<'_> {
        // Slot fields need local storage; the caller supplies those separately.
        let mut identity = ResourceIdentity::default();
        identity.module = self.module.identity();
        identity.token = self.identity();
        identity
    }
    pub(crate) fn matches_location(&self, uri: &Pkcs11Uri) -> Result<bool, Error> {
        let slot = self.module.slot_info(self.slot)?;
        let mut resource = self.resource_identity();
        resource.slot.id = Some(self.slot.id());
        resource.slot.description = Some(slot.slot_description());
        resource.slot.manufacturer = Some(slot.manufacturer_id());
        Ok(uri.module_selector().matches(&resource.module)
            && uri.slot_selector().matches(&resource.slot)
            && uri.token_selector().matches(&resource.token))
    }
}

/// Validate token-only URI constraints without loading or inspecting a module.
/// Rejects object criteria, credentials and unsupported path/query attributes.
pub fn validate_token_uri(uri: &Pkcs11Uri) -> Result<(), Error> {
    if uri.has_unknown_path_attributes()
        || ["object", "id", "type"]
            .iter()
            .any(|name| uri.path_attribute(name).is_some())
        || uri.query_names().any(|name| name != "module-path")
    {
        return Err(Error::InvalidTokenReference);
    }
    Ok(())
}

fn token_identity(info: &TokenInfo) -> TokenIdentity<'_> {
    let mut result = TokenIdentity::default();
    result.label = Some(info.label());
    result.manufacturer = Some(info.manufacturer_id());
    result.model = Some(info.model());
    result.serial = Some(info.serial_number());
    result
}
pub(crate) fn same_token(a: &TokenInfo, b: &TokenInfo) -> bool {
    a.label() == b.label()
        && a.manufacturer_id() == b.manufacturer_id()
        && a.model() == b.model()
        && a.serial_number() == b.serial_number()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_uris_reject_ignored_constraints_and_credentials() {
        for uri in [
            "pkcs11:token=test;object=key",
            "pkcs11:token=test;id=%01",
            "pkcs11:type=private",
            "pkcs11:vendor=extension",
            "pkcs11:?pin-value=secret",
            "pkcs11:?pin-source=file:/secret",
            "pkcs11:?module-name=ignored",
        ] {
            assert!(matches!(
                validate_token_uri(&uri.parse().unwrap()),
                Err(Error::InvalidTokenReference)
            ));
        }
        for uri in [
            "pkcs11:",
            "pkcs11:token=test;slot-id=1;library-description=module",
        ] {
            validate_token_uri(&uri.parse().unwrap()).unwrap();
        }
        let path = std::env::current_dir().unwrap().join("module.so");
        let uri = Pkcs11Uri::builder()
            .query_attribute("module-path", path.to_str().unwrap().into())
            .unwrap()
            .build()
            .unwrap();
        validate_token_uri(&uri).unwrap();
    }
}
