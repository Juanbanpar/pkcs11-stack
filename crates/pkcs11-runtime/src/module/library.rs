// SPDX-License-Identifier: MIT OR Apache-2.0
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use pkcs11_locator::{ModuleIdentity, Pkcs11Uri};
use std::{
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{Error, LibraryInfo, Session, SessionMode, Slot, SlotInfo, error::backend};

use super::Token;

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
    /// Initialize or erase a token in a diagnostic slot, using the supplied SO PIN.
    /// Requires exclusive module access, so no borrowed tokens/sessions can survive.
    /// Existing token contents can be destroyed. No retry or implicit selection.
    pub fn initialize_token(
        &mut self,
        slot: Slot,
        pin: &crate::SecretText,
        label: &str,
    ) -> Result<(), Error> {
        if label.len() > 32 {
            return Err(Error::InvalidParameters(
                "token label exceeds 32 UTF-8 bytes",
            ));
        }
        self.raw()?
            .init_token(
                slot,
                &cryptoki::types::AuthPin::from(pin.expose_secret()),
                label,
            )
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

    pub(super) fn identity(&self) -> ModuleIdentity<'_> {
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
