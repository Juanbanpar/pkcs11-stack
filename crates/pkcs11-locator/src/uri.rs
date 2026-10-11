// SPDX-License-Identifier: MIT OR Apache-2.0
use std::{collections::BTreeMap, fmt, str::FromStr};

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::{ModuleSelector, ObjectSelector, SlotSelector, TokenSelector, codec};

/// A parsing/construction failure. Never contains input, attribute names or values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The scheme is not pkcs11.
    #[error("expected the pkcs11 URI scheme")]
    Scheme,
    /// Missing equals sign, invalid name, or empty attribute between separators.
    #[error("invalid attribute syntax")]
    Attribute,
    /// A percent escape is incomplete or contains non-hexadecimal digits.
    #[error("invalid percent encoding")]
    PercentEncoding,
    /// A literal byte is outside the RFC 7512 component grammar.
    #[error("invalid literal URI character")]
    Character,
    /// Textual data is not UTF-8.
    #[error("attribute requires UTF-8 text")]
    Utf8,
    /// A non-repeatable attribute was specified twice.
    #[error("duplicate attribute")]
    Duplicate,
    /// A standard attribute appears in the wrong URI component.
    #[error("attribute in wrong URI component")]
    Component,
    /// Unknown storage object class.
    #[error("unsupported object type")]
    ObjectType,
    /// Invalid or overflowing decimal slot ID or library version.
    #[error("invalid numeric attribute")]
    Number,
    /// A value cannot fit its PKCS#11 metadata field or character set.
    #[error("invalid PKCS#11 metadata value")]
    Metadata,
    /// Both ways of supplying a PIN were specified.
    #[error("pin-source and pin-value are mutually exclusive")]
    PinConflict,
    /// Module paths must be absolute on the current platform and contain no NUL.
    #[error("module-path must be an absolute path without NUL")]
    ModulePath,
}

/// RFC 7512 storage object classes, independent of cryptoki.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectType {
    /// Public key.
    Public,
    /// Private key.
    Private,
    /// Certificate.
    Certificate,
    /// Secret key.
    SecretKey,
    /// Data object.
    Data,
}

impl ObjectType {
    /// The RFC attribute value for this class.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Certificate => "cert",
            Self::SecretKey => "secret-key",
            Self::Data => "data",
        }
    }
}

impl FromStr for ObjectType {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self, Error> {
        match value.to_ascii_lowercase().as_str() {
            "public" => Ok(Self::Public),
            "private" => Ok(Self::Private),
            "cert" => Ok(Self::Certificate),
            "secret-key" => Ok(Self::SecretKey),
            "data" => Ok(Self::Data),
            _ => Err(Error::ObjectType),
        }
    }
}

pub(crate) const PATH_NAMES: &[&str] = &[
    "token",
    "manufacturer",
    "serial",
    "model",
    "library-manufacturer",
    "library-version",
    "library-description",
    "object",
    "type",
    "id",
    "slot-description",
    "slot-manufacturer",
    "slot-id",
];
const QUERY_NAMES: &[&str] = &["pin-source", "pin-value", "module-name", "module-path"];

/// Validated URI data. Display and Debug redact PIN values and sources.
///
/// No implicit secret-bearing Clone, equality or full URI comparison is provided.
/// Query values are protected even for vendor attributes. No I/O is performed.
#[derive(Default)]
pub struct Pkcs11Uri {
    pub(crate) path: BTreeMap<String, Vec<u8>>,
    pub(crate) query: BTreeMap<String, Vec<SecretString>>,
}

impl Pkcs11Uri {
    /// Construct a URI from decoded attributes.
    pub fn builder() -> Pkcs11UriBuilder {
        Pkcs11UriBuilder::default()
    }

    /// Decoded path attribute, including binary IDs; names are case-insensitive.
    pub fn path_attribute(&self, name: &str) -> Option<&[u8]> {
        self.path.get(&name.to_ascii_lowercase()).map(Vec::as_slice)
    }

    /// Protected query values in insertion order for this name.
    ///
    /// Use secrecy's ExposeSecret explicitly to read them. Vendor duplicates are retained.
    pub fn query_values(&self, name: &str) -> impl Iterator<Item = &SecretString> {
        self.query
            .get(&name.to_ascii_lowercase())
            .into_iter()
            .flatten()
    }

    /// Decoded path attributes in deterministic name order.
    pub fn path_attributes(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.path
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
    }

    /// Query names in deterministic order, without exposing their values.
    pub fn query_names(&self) -> impl Iterator<Item = &str> {
        self.query.keys().map(String::as_str)
    }

    /// Whether matching must fail because an unknown path constraint is present.
    pub fn has_unknown_path_attributes(&self) -> bool {
        self.path
            .keys()
            .any(|key| !PATH_NAMES.contains(&key.as_str()))
    }

    /// Module criteria derived from this URI. Does not select tokens or objects.
    pub fn module_selector(&self) -> ModuleSelector<'_> {
        ModuleSelector(self)
    }
    /// Slot criteria derived from this URI. Does not select modules or tokens.
    pub fn slot_selector(&self) -> SlotSelector<'_> {
        SlotSelector(self)
    }
    /// Token criteria derived from this URI. Does not select modules or objects.
    pub fn token_selector(&self) -> TokenSelector<'_> {
        TokenSelector(self)
    }
    /// Object criteria derived from this URI. Does not select modules or tokens.
    pub fn object_selector(&self) -> ObjectSelector<'_> {
        ObjectSelector(self)
    }

    /// Deterministic, explicitly secret-inclusive URI serialization.
    ///
    /// The returned SecretString redacts Debug and zeroizes on drop. Exposing it
    /// is deliberate; callers remain responsible for any further copies/logging.
    pub fn to_secret_uri(&self) -> SecretString {
        // Reserve exactly the encoded length before writing any secrets, avoiding
        // reallocations that could leave previous secret-bearing buffers behind.
        let mut len = "pkcs11:".len();
        for (index, (name, value)) in self.path.iter().enumerate() {
            len +=
                usize::from(index != 0) + name.len() + 1 + codec::encoded_len(value, name == "id");
        }
        for (name, values) in &self.query {
            for value in values {
                len += name.len() + 2 + codec::encoded_len(value.expose_secret().as_bytes(), false);
            }
        }
        let mut out = Zeroizing::new(String::with_capacity(len));
        self.render(&mut out, true);
        SecretString::from(std::mem::take(&mut *out))
    }

    pub(crate) fn query_text(&self, name: &str) -> Option<&str> {
        self.query
            .get(name)?
            .first()
            .map(ExposeSecret::expose_secret)
    }

    fn render(&self, out: &mut String, secrets: bool) {
        out.push_str("pkcs11:");
        for (i, (name, value)) in self.path.iter().enumerate() {
            if i != 0 {
                out.push(';');
            }
            out.push_str(name);
            out.push('=');
            codec::encode(out, value, name == "id");
        }
        let mut delimiter = '?';
        for (name, values) in &self.query {
            for value in values {
                out.push(delimiter);
                delimiter = '&';
                out.push_str(name);
                out.push('=');
                if !secrets && matches!(name.as_str(), "pin-value" | "pin-source") {
                    out.push_str("[REDACTED]");
                } else {
                    codec::encode(out, value.expose_secret().as_bytes(), false);
                }
            }
        }
    }
}

impl fmt::Display for Pkcs11Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        self.render(&mut out, false);
        f.write_str(&out)
    }
}
impl fmt::Debug for Pkcs11Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The URI Display is deliberately the only formatting path.
        write!(f, "Pkcs11Uri({self})")
    }
}

impl FromStr for Pkcs11Uri {
    type Err = Error;
    fn from_str(input: &str) -> Result<Self, Error> {
        let (scheme, rest) = input.split_once(':').ok_or(Error::Scheme)?;
        if !scheme.eq_ignore_ascii_case("pkcs11") {
            return Err(Error::Scheme);
        }
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let mut builder = Self::builder();
        if !path.is_empty() {
            for pair in path.split(';') {
                let (name, value) = pair.split_once('=').ok_or(Error::Attribute)?;
                // Numeric attributes and object types have dedicated literal grammar.
                if (name.eq_ignore_ascii_case("slot-id")
                    || name.eq_ignore_ascii_case("library-version"))
                    && value.contains('%')
                {
                    return Err(Error::Number);
                }
                if name.eq_ignore_ascii_case("type") && value.contains('%') {
                    return Err(Error::ObjectType);
                }
                builder = builder.path_attribute(name, &codec::decode(value, false)?)?;
            }
        }
        if !query.is_empty() {
            for pair in query.split('&') {
                let (name, value) = pair.split_once('=').ok_or(Error::Attribute)?;
                let bytes = codec::decode(value, true)?;
                let text = std::str::from_utf8(&bytes).map_err(|_| Error::Utf8)?;
                builder = builder.query_attribute(name, SecretString::from(text))?;
            }
        }
        builder.build()
    }
}

/// Validating construction from decoded attributes; never percent-encode inputs.
#[derive(Default, Debug)]
pub struct Pkcs11UriBuilder(Pkcs11Uri);

impl Pkcs11UriBuilder {
    /// Add a path attribute. Repeated names are errors, never silent overwrites.
    pub fn path_attribute(mut self, name: &str, value: &[u8]) -> Result<Self, Error> {
        let name = normalize_name(name)?;
        if QUERY_NAMES.contains(&name.as_str()) {
            return Err(Error::Component);
        }
        if self.0.path.contains_key(&name) {
            return Err(Error::Duplicate);
        }
        let value = validate_path(&name, value)?;
        self.0.path.insert(name, value);
        Ok(self)
    }

    /// Add a decoded query value, transferring ownership of protected storage.
    ///
    /// Standard attributes are unique; vendor attributes may repeat. PIN sources
    /// are stored only: no files, commands, environment or network are consulted.
    pub fn query_attribute(mut self, name: &str, value: SecretString) -> Result<Self, Error> {
        let name = normalize_name(name)?;
        if PATH_NAMES.contains(&name.as_str()) {
            return Err(Error::Component);
        }
        if QUERY_NAMES.contains(&name.as_str()) && self.0.query.contains_key(&name) {
            return Err(Error::Duplicate);
        }
        if name == "module-path"
            && (value.expose_secret().contains('\0')
                || !std::path::Path::new(value.expose_secret()).is_absolute())
        {
            return Err(Error::ModulePath);
        }
        self.0.query.entry(name).or_default().push(value);
        Ok(self)
    }

    /// Finish construction, rejecting mutually exclusive authentication sources.
    pub fn build(self) -> Result<Pkcs11Uri, Error> {
        if self.0.query.contains_key("pin-value") && self.0.query.contains_key("pin-source") {
            return Err(Error::PinConflict);
        }
        Ok(self.0)
    }
}

fn normalize_name(name: &str) -> Result<String, Error> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::Attribute);
    }
    Ok(name.to_ascii_lowercase())
}

fn decimal<T: FromStr>(text: &str) -> Result<T, Error> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Number);
    }
    // Ignore redundant zeroes before conversion so even long zero prefixes work.
    let digits = text.trim_start_matches('0');
    (if digits.is_empty() { "0" } else { digits })
        .parse()
        .map_err(|_| Error::Number)
}

fn validate_path(name: &str, value: &[u8]) -> Result<Vec<u8>, Error> {
    if name == "id" {
        return Ok(value.to_vec());
    }
    let text = std::str::from_utf8(value).map_err(|_| Error::Utf8)?;
    match name {
        "type" => return Ok(text.parse::<ObjectType>()?.as_str().as_bytes().to_vec()),
        "slot-id" => return Ok(decimal::<u64>(text)?.to_string().into_bytes()),
        "library-version" => {
            let (major, minor) = text.split_once('.').unwrap_or((text, "0"));
            return Ok(format!("{}.{}", decimal::<u8>(major)?, decimal::<u8>(minor)?).into_bytes());
        }
        _ => {}
    }
    let limit = match name {
        "token"
        | "manufacturer"
        | "library-manufacturer"
        | "library-description"
        | "slot-manufacturer" => Some(32),
        "model" | "serial" => Some(16),
        "slot-description" => Some(64),
        _ => None,
    };
    if limit.is_some_and(|max| value.len() > max || value.contains(&0))
        || (name == "serial" && !value.is_ascii())
    {
        return Err(Error::Metadata);
    }
    Ok(value.to_vec())
}
