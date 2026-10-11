// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{ObjectType, Pkcs11Uri};

/// Discovered library/module metadata. Missing fields are unknown, not empty.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct ModuleIdentity<'a> {
    /// Library manufacturer, optionally space-padded to the PKCS#11 field width.
    pub manufacturer: Option<&'a str>,
    /// Library description, optionally space-padded.
    pub description: Option<&'a str>,
    /// Library major and minor version.
    pub version: Option<(u8, u8)>,
    /// Logical module name without platform prefixes or suffixes.
    pub name: Option<&'a str>,
    /// Absolute module path, or a selected module-directory path.
    pub path: Option<&'a str>,
}

/// Discovered slot metadata; a slot ID is not a persistent token identity.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SlotIdentity<'a> {
    /// Slot manufacturer, optionally space-padded.
    pub manufacturer: Option<&'a str>,
    /// Slot description, optionally space-padded.
    pub description: Option<&'a str>,
    /// Numeric slot ID for this module instance.
    pub id: Option<u64>,
}

/// Discovered token metadata, separate from selection criteria and sessions.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct TokenIdentity<'a> {
    /// Token label, optionally space-padded.
    pub label: Option<&'a str>,
    /// Token manufacturer, optionally space-padded.
    pub manufacturer: Option<&'a str>,
    /// Token model, optionally space-padded.
    pub model: Option<&'a str>,
    /// Token serial number, optionally space-padded.
    pub serial: Option<&'a str>,
}

/// Discovered storage object metadata. No object handle is stored here.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct ObjectIdentity<'a> {
    /// Exact CKA_LABEL; unlike fixed-width metadata, spaces are significant.
    pub label: Option<&'a str>,
    /// Exact binary CKA_ID, including empty IDs and zero bytes.
    pub id: Option<&'a [u8]>,
    /// Storage object class.
    pub object_type: Option<ObjectType>,
}

/// All discovery context needed to enforce a URI's constraints together.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct ResourceIdentity<'a> {
    /// Library and module metadata.
    pub module: ModuleIdentity<'a>,
    /// Slot metadata.
    pub slot: SlotIdentity<'a>,
    /// Token metadata.
    pub token: TokenIdentity<'a>,
    /// Object metadata.
    pub object: ObjectIdentity<'a>,
}

/// Borrowed module-only criteria; use Pkcs11Uri::matches for complete selection.
#[derive(Debug, Clone, Copy)]
pub struct ModuleSelector<'a>(pub(crate) &'a Pkcs11Uri);
/// Borrowed slot-only criteria; use Pkcs11Uri::matches for complete selection.
#[derive(Debug, Clone, Copy)]
pub struct SlotSelector<'a>(pub(crate) &'a Pkcs11Uri);
/// Borrowed token-only criteria; use Pkcs11Uri::matches for complete selection.
#[derive(Debug, Clone, Copy)]
pub struct TokenSelector<'a>(pub(crate) &'a Pkcs11Uri);
/// Borrowed object-only criteria; use Pkcs11Uri::matches for complete selection.
#[derive(Debug, Clone, Copy)]
pub struct ObjectSelector<'a>(pub(crate) &'a Pkcs11Uri);

impl Pkcs11Uri {
    /// Match all module, slot, token and object constraints against discovery data.
    ///
    /// Unknown path attributes fail closed. Unknown query attributes are ignored.
    /// PIN attributes have no matching effect; authentication is outside this crate.
    pub fn matches(&self, identity: &ResourceIdentity<'_>) -> bool {
        self.module_selector().matches(&identity.module)
            && self.slot_selector().matches(&identity.slot)
            && self.token_selector().matches(&identity.token)
            && self.object_selector().matches(&identity.object)
    }

    fn bytes_match(&self, name: &str, actual: Option<&[u8]>) -> bool {
        self.path_attribute(name)
            .is_none_or(|expected| actual == Some(expected))
    }

    fn text_matches(&self, name: &str, actual: Option<&str>, padded: bool) -> bool {
        self.bytes_match(
            name,
            actual
                .map(|s| if padded { s.trim_end_matches(' ') } else { s })
                .map(str::as_bytes),
        )
    }
}

impl ModuleSelector<'_> {
    /// Match library metadata and query module restrictions, jointly if both exist.
    ///
    /// Logical names use ASCII case-insensitive comparison. Paths compare exactly,
    /// without filesystem access or symlink/directory resolution. Discovery must
    /// decide whether a module-path names a library or directory and supply the
    /// corresponding path. Other text uses exact UTF-8 bytes after padding removal.
    pub fn matches(&self, actual: &ModuleIdentity<'_>) -> bool {
        let uri = self.0;
        !uri.has_unknown_path_attributes()
            && uri.text_matches("library-manufacturer", actual.manufacturer, true)
            && uri.text_matches("library-description", actual.description, true)
            && uri.text_matches(
                "library-version",
                actual.version.map(|(a, b)| format!("{a}.{b}")).as_deref(),
                false,
            )
            && uri
                .query_text("module-name")
                .is_none_or(|v| actual.name.is_some_and(|n| n.eq_ignore_ascii_case(v)))
            && uri
                .query_text("module-path")
                .is_none_or(|v| actual.path == Some(v))
    }
}

impl SlotSelector<'_> {
    /// Match slot fields only. Unknown path constraints always prevent a match.
    pub fn matches(&self, actual: &SlotIdentity<'_>) -> bool {
        let uri = self.0;
        !uri.has_unknown_path_attributes()
            && uri.text_matches("slot-manufacturer", actual.manufacturer, true)
            && uri.text_matches("slot-description", actual.description, true)
            && uri.text_matches(
                "slot-id",
                actual.id.map(|id| id.to_string()).as_deref(),
                false,
            )
    }
}

impl TokenSelector<'_> {
    /// Match token fields only, stripping ASCII space padding from actual fields.
    ///
    /// UTF-8 is compared exactly; no implicit Unicode normalization is applied.
    pub fn matches(&self, actual: &TokenIdentity<'_>) -> bool {
        let uri = self.0;
        !uri.has_unknown_path_attributes()
            && uri.text_matches("token", actual.label, true)
            && uri.text_matches("manufacturer", actual.manufacturer, true)
            && uri.text_matches("model", actual.model, true)
            && uri.text_matches("serial", actual.serial, true)
    }
}

impl ObjectSelector<'_> {
    /// Match object label, binary ID and class. All supplied constraints must match.
    pub fn matches(&self, actual: &ObjectIdentity<'_>) -> bool {
        let uri = self.0;
        !uri.has_unknown_path_attributes()
            && uri.text_matches("object", actual.label, false)
            && uri.bytes_match("id", actual.id)
            && uri.text_matches("type", actual.object_type.map(ObjectType::as_str), false)
    }
}
