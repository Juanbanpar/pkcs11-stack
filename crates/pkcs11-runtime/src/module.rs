// SPDX-License-Identifier: MIT OR Apache-2.0
use std::{
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::RvError,
};
use pkcs11_locator::{ModuleIdentity, Pkcs11Uri, ResourceIdentity, TokenIdentity, TokenSelector};

use crate::{
    Error, LibraryInfo, MechanismInfo, MechanismType, Session, SessionMode, Slot, SlotInfo,
    TokenInfo,
    error::{backend, unique},
};

/// Owns one successful initialization of a trusted PKCS#11 library.
///
/// Sessions borrow this owner or retain it through shared ownership.
/// No raw context or independent clone escapes.
/// Already-initialized modules are rejected, never adopted or finalized.
/// Do not mix independent lifecycle owners for the same module in one process.
/// Explicit finalize reports errors; Drop attempts best-effort finalization.
pub struct Module {
    raw: Option<Pkcs11>,
    path: PathBuf,
    info: LibraryInfo,
}

impl std::fmt::Debug for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Module")
            .field("path", &self.path)
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl Module {
    /// Open a session that retains this initialization owner until it closes.
    /// No new module is loaded. Drop owned sessions before explicit finalization.
    pub fn open_owned_session(
        self: &Arc<Self>,
        uri: &Pkcs11Uri,
        mode: SessionMode,
    ) -> Result<Session<'static>, Error> {
        let token = self.resolve_token_uri(uri)?;
        let token = Token {
            module: ModuleRef::Shared(self.clone()),
            slot: token.slot,
            info: token.info.clone(),
        };
        token.open_session(mode)
    }

    /// Load a trusted shared library and initialize with native OS locking enabled.
    ///
    /// Module loading executes vendor code. There is no URI-driven automatic load.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().canonicalize().map_err(Error::ModulePath)?;
        let raw = Pkcs11::new(&path).map_err(|e| backend("load module", e))?;
        // On failure (including AlreadyInitialized), do not call C_Finalize.
        raw.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| backend("initialize module", e))?;
        let info = match raw.get_library_info() {
            Ok(info) => info,
            Err(error) => {
                return Err(match raw.finalize() {
                    Ok(()) => backend("library info", error),
                    Err(cleanup) => Error::InitializationCleanup {
                        source: error,
                        cleanup,
                    },
                });
            }
        };
        Ok(Self {
            raw: Some(raw),
            path,
            info,
        })
    }

    pub(crate) fn raw(&self) -> Result<&Pkcs11, Error> {
        self.raw.as_ref().ok_or(Error::Closed)
    }

    /// Canonical path of this explicitly configured module.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Library metadata captured after successful initialization.
    pub fn info(&self) -> &LibraryInfo {
        &self.info
    }
    /// Enumerate every slot, or only slots currently containing a token.
    pub fn slots(&self, token_present: bool) -> Result<Vec<Slot>, Error> {
        let raw = self.raw()?;
        (if token_present {
            raw.get_slots_with_token()
        } else {
            raw.get_all_slots()
        })
        .map_err(|e| backend("list slots", e))
    }
    /// Read slot metadata, keeping numeric IDs diagnostic rather than persistent.
    pub fn slot_info(&self, slot: Slot) -> Result<SlotInfo, Error> {
        self.raw()?
            .get_slot_info(slot)
            .map_err(|e| backend("slot info", e))
    }
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
    /// Initialize or erase a token in a diagnostic slot, using the supplied SO PIN.
    /// Requires exclusive module access, so no borrowed tokens/sessions can survive.
    /// Existing token contents can be destroyed. No retry or implicit selection.
    pub fn initialize_token(
        &mut self,
        slot: Slot,
        pin: &secrecy::SecretString,
        label: &str,
    ) -> Result<(), Error> {
        if label.len() > 32 {
            return Err(Error::InvalidParameters(
                "token label exceeds 32 UTF-8 bytes",
            ));
        }
        self.raw()?
            .init_token(slot, pin, label)
            .map_err(|e| backend("initialize token", e))
    }
    /// Finalize an owned initialization. Active borrowed sessions prevent this call.
    /// Owned pools must release their Arcs before the final owner can be unwrapped.
    pub fn finalize(mut self) -> Result<(), Error> {
        self.raw
            .take()
            .ok_or(Error::Closed)?
            .finalize()
            .map_err(|e| backend("finalize module", e))
    }

    pub(crate) fn identity(&self) -> ModuleIdentity<'_> {
        let mut result = ModuleIdentity::default();
        result.manufacturer = Some(self.info.manufacturer_id());
        result.description = Some(self.info.library_description());
        result.version = Some((
            self.info.library_version().major(),
            self.info.library_version().minor(),
        ));
        result.path = self.path.to_str();
        result
    }
}
impl Drop for Module {
    fn drop(&mut self) {
        if let Some(raw) = self.raw.take() {
            let _ = raw.finalize();
        }
    }
}

// Borrowed and owned pools share one initialization owner and the same session code.
#[derive(Clone, Debug)]
pub(crate) enum ModuleRef<'m> {
    Borrowed(&'m Module),
    Shared(Arc<Module>),
}
impl Deref for ModuleRef<'_> {
    type Target = Module;
    fn deref(&self) -> &Module {
        match self {
            Self::Borrowed(module) => module,
            Self::Shared(module) => module,
        }
    }
}

/// Discovered token with stable metadata, bound to its owning module.
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
    pub(crate) fn resource_identity(&self) -> ResourceIdentity<'_> {
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

pub(crate) fn token_identity(info: &TokenInfo) -> TokenIdentity<'_> {
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
