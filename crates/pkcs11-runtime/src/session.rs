// SPDX-License-Identifier: MIT OR Apache-2.0
use std::fmt;

use cryptoki::{object::ObjectHandle, session::UserType};
use pkcs11_locator::{ObjectIdentity, ObjectType, Pkcs11Uri};
use secrecy::SecretString;

use crate::{
    Attribute, AttributeInfo, AttributeType, Error, ObjectClass, SessionInfo, Token,
    error::{backend, unique},
};

/// Session access mode. No pool or hidden worker is involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    /// Read-only session.
    ReadOnly,
    /// Read-write session.
    ReadWrite,
}
/// Explicit PIN input, borrowed only for the login call.
#[derive(Debug)]
#[non_exhaustive]
pub enum Pin<'a> {
    /// Host-supplied PIN held in redacted, zeroizing storage.
    Value(&'a SecretString),
    /// Token-provided protected authentication path, checked before login.
    ProtectedPath,
}
/// Explicit login policy; this does not cache credentials or implicit login state.
///
/// Context-specific authentication belongs to `Session::sign`, after operation init.
#[derive(Debug)]
#[non_exhaustive]
pub enum Authentication<'a> {
    /// Do not change token authentication state (not an implicit logout).
    None,
    /// Login as the normal USER.
    User(Pin<'a>),
    /// Login as SO, requiring an RW session and no conflicting RO sessions.
    SecurityOfficer(Pin<'a>),
}

/// Exclusive session retaining its module through its token identity.
/// The owner is borrowed for direct sessions or shared for owned-pool sessions.
///
/// Authentication and close require exclusive access. No raw handle is public.
/// Failed operations that invalidate the session make subsequent session/object
/// calls return `Error::Closed`. Explicit close remains available for cleanup.
/// Drop closes but never explicitly logs out the token. Closing the last session
/// may nevertheless reset token-wide authentication under PKCS#11 semantics.
pub struct Session<'m> {
    raw: Option<cryptoki::session::Session>,
    token: Token<'m>,
    pub(crate) mode: SessionMode,
    pub(crate) healthy: std::cell::Cell<bool>,
}
impl fmt::Debug for Session<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("slot", &self.token.slot)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl<'m> Session<'m> {
    pub(crate) fn open(token: &Token<'m>, mode: SessionMode) -> Result<Self, Error> {
        token.validate()?;
        let raw = match mode {
            SessionMode::ReadOnly => token.module.raw()?.open_ro_session(token.slot),
            SessionMode::ReadWrite => token.module.raw()?.open_rw_session(token.slot),
        }
        .map_err(|e| backend("open session", e))?;
        let session = Self {
            raw: Some(raw),
            token: Token {
                module: token.module.clone(),
                slot: token.slot,
                info: token.info.clone(),
            },
            mode,
            healthy: std::cell::Cell::new(true),
        };
        session.token.validate()?;
        Ok(session)
    }
    pub(crate) fn raw(&self) -> Result<&cryptoki::session::Session, Error> {
        if !self.healthy.get() {
            return Err(Error::Closed);
        }
        self.raw.as_ref().ok_or(Error::Closed)
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.raw()?;
        self.token
            .validate()
            .inspect_err(|_| self.healthy.set(false))
    }
    fn failed(&self, operation: &'static str, source: cryptoki::error::Error) -> Error {
        self.healthy.set(false);
        backend(operation, source)
    }
    /// Validate current protected-path capability using the same identity check
    /// for ordinary and context-specific authentication.
    pub(crate) fn login_pin<'a>(&self, pin: Pin<'a>) -> Result<Option<&'a SecretString>, Error> {
        self.validate()?;
        match pin {
            Pin::Value(secret) => Ok(Some(secret)),
            Pin::ProtectedPath => {
                let current = self
                    .token
                    .module
                    .token(self.token.slot)
                    .inspect_err(|_| self.healthy.set(false))?;
                if !crate::module::same_token(self.token.info(), current.info()) {
                    self.healthy.set(false);
                    return Err(Error::TokenChanged);
                }
                if !current.info().protected_authentication_path() {
                    return Err(Error::ProtectedPathUnavailable);
                }
                Ok(None)
            }
        }
    }
    fn find_handles(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>, Error> {
        self.validate()?;
        let raw = self.raw()?;
        // Keep failed operations and caught panics from leaving a reusable session.
        self.healthy.set(false);
        let handles = raw
            .find_objects(template)
            .map_err(|e| backend("find objects", e))?;
        self.healthy.set(true);
        Ok(handles)
    }
    /// Snapshot token metadata bound to this session.
    pub fn token(&self) -> &Token<'m> {
        &self.token
    }
    /// Inspect actual session state rather than assuming a cached login state.
    pub fn info(&self) -> Result<SessionInfo, Error> {
        self.validate()?;
        self.raw()?
            .get_session_info()
            .map_err(|e| self.failed("session info", e))
    }
    /// Apply an explicit authentication policy without storing PINs or retrying.
    ///
    /// USER/SO login state is shared by this application's sessions on the token.
    /// Already-logged-in and conflicting-user states retain their PKCS#11 errors.
    pub fn authenticate(&mut self, policy: Authentication<'_>) -> Result<(), Error> {
        self.validate()?;
        let (user, pin) = match policy {
            Authentication::None => return Ok(()),
            Authentication::User(pin) => (UserType::User, pin),
            Authentication::SecurityOfficer(pin) => {
                if self.mode != SessionMode::ReadWrite {
                    return Err(Error::ReadWriteRequired);
                }
                (UserType::So, pin)
            }
        };
        let pin = self.login_pin(pin)?;
        self.raw()?
            .login(user, pin)
            .map_err(|e| backend("login", e))
    }
    /// Explicit token-wide logout; it can invalidate private handles in other sessions.
    pub fn logout(&mut self) -> Result<(), Error> {
        self.validate()?;
        self.raw()?.logout().map_err(|e| backend("logout", e))
    }
    /// Fill a nonempty caller buffer using the token's advertised RNG, once.
    /// No software fallback or retry is performed. Discard the buffer on failure.
    pub fn generate_random(&mut self, output: &mut [u8]) -> Result<(), Error> {
        if output.is_empty() {
            return Err(Error::InvalidParameters("empty random output"));
        }
        self.validate()?;
        let current = self
            .token
            .module
            .token(self.token.slot)
            .inspect_err(|_| self.healthy.set(false))?;
        if !crate::module::same_token(self.token.info(), current.info()) {
            self.healthy.set(false);
            return Err(Error::TokenChanged);
        }
        if !current.info().rng() {
            return Err(Error::RandomUnavailable);
        }
        let raw = self.raw()?;
        self.healthy.set(false);
        let result = raw
            .generate_random_slice(output)
            .map_err(|e| backend("generate random", e));
        if result.is_ok() {
            self.healthy.set(true);
        }
        result
    }
    /// Close the session and report closure failures. No automatic logout call.
    pub fn close(mut self) -> Result<(), Error> {
        self.raw
            .take()
            .ok_or(Error::Closed)?
            .close()
            .map_err(|e| backend("close session", e))
    }
    /// Search a generic cryptoki template and return session-bound objects.
    ///
    /// Templates are never logged. This search may return session or token objects.
    /// The returned objects cannot be transferred to another session.
    pub fn find_objects(&mut self, template: &[Attribute]) -> Result<Vec<Object<'_, 'm>>, Error> {
        let handles = self.find_handles(template)?;
        Ok(handles
            .into_iter()
            .map(|handle| Object {
                session: self,
                handle,
            })
            .collect())
    }
    /// Resolve a stable reference afresh in this session. Only token objects qualify.
    ///
    /// All URI constraints are checked, including module, slot and token metadata;
    /// no match or multiple matches is an error. No handle is cached in ObjectRef.
    pub fn resolve(&mut self, reference: &ObjectRef) -> Result<Object<'_, 'm>, Error> {
        self.validate()?;
        if !self
            .token
            .matches_location(&reference.uri)
            .inspect_err(|_| self.healthy.set(false))?
        {
            return Err(Error::NotFound("object"));
        }
        let template = reference.template();
        let handles = self.find_handles(&template)?;
        let raw = self.raw()?;
        let mut matches = Vec::new();
        for handle in handles {
            let values = raw
                .get_attributes(
                    handle,
                    &[
                        AttributeType::Class,
                        AttributeType::Label,
                        AttributeType::Id,
                        AttributeType::Token,
                    ],
                )
                .map_err(|e| self.failed("object identity", e))?;
            let mut identity = ObjectIdentity::default();
            let mut token_object = false;
            for value in &values {
                match value {
                    Attribute::Label(v) => identity.label = std::str::from_utf8(v).ok(),
                    Attribute::Id(v) => identity.id = Some(v),
                    Attribute::Class(v) => identity.object_type = object_type(*v),
                    Attribute::Token(v) => token_object = *v,
                    _ => {}
                }
            }
            if token_object
                && identity.object_type.is_some()
                && reference.uri.object_selector().matches(&identity)
            {
                matches.push(handle);
            }
        }
        let handle = unique(matches, "object")?;
        Ok(Object {
            session: self,
            handle,
        })
    }
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        // An explicit Drop implementation also makes Rust's drop checking retain
        // the module borrow through session destruction, even after the last use.
        // Owned sessions likewise retain their Arc until after raw closure.
        // cryptoki closes the taken session; it does not issue C_Logout here.
        drop(self.raw.take());
    }
}

/// A persistent, secret-free locator, never a PKCS#11 handle.
#[derive(Debug)]
pub struct ObjectRef {
    uri: Pkcs11Uri,
}
impl ObjectRef {
    /// Create a token-object reference with at least one token and object constraint.
    ///
    /// Reject PINs, unknown constraints, slot IDs and unimplemented query selectors.
    /// Module-path is supported and must match the loaded canonical path exactly.
    pub fn new(uri: Pkcs11Uri) -> Result<Self, Error> {
        let has_token = ["token", "manufacturer", "model", "serial"]
            .iter()
            .any(|n| uri.path_attribute(n).is_some());
        let has_object = ["object", "id", "type"]
            .iter()
            .any(|n| uri.path_attribute(n).is_some());
        if !has_token
            || !has_object
            || uri.has_unknown_path_attributes()
            || uri.path_attribute("slot-id").is_some()
            || uri.query_names().any(|n| n != "module-path")
        {
            return Err(Error::InvalidObjectReference);
        }
        Ok(Self { uri })
    }
    /// Persistent URI data; credential query attributes were rejected at construction.
    pub fn uri(&self) -> &Pkcs11Uri {
        &self.uri
    }
    fn template(&self) -> Vec<Attribute> {
        let mut template = vec![Attribute::Token(true)];
        if let Some(id) = self.uri.path_attribute("id") {
            template.push(Attribute::Id(id.to_vec()));
        }
        if let Some(label) = self.uri.path_attribute("object") {
            template.push(Attribute::Label(label.to_vec()));
        }
        if let Some(kind) = self
            .uri
            .path_attribute("type")
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|v| v.parse::<ObjectType>().ok())
        {
            if let Some(class) = object_class(kind) {
                template.push(Attribute::Class(class));
            }
        }
        template
    }
}

/// An operational object bound to its originating live session.
///
/// No handle getter, Clone or cross-session operation API is provided.
pub struct Object<'s, 'm> {
    pub(crate) session: &'s Session<'m>,
    pub(crate) handle: ObjectHandle,
}
impl fmt::Debug for Object<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Object { session_bound: true }")
    }
}
impl Object<'_, '_> {
    /// Inspect per-attribute availability/size, including Sensitive and TypeInvalid.
    pub fn attribute_info(&self, types: &[AttributeType]) -> Result<Vec<AttributeInfo>, Error> {
        self.session.validate()?;
        self.session
            .raw()?
            .get_attribute_info(self.handle, types)
            .map_err(|e| self.session.failed("attribute info", e))
    }
    /// Read requested attributes. Unavailable attributes may be absent in cryptoki's result.
    ///
    /// Use attribute_info to distinguish sensitive/invalid attributes. Debug of the
    /// returned container lists types only. Explicit value access can expose secret
    /// material for extractable objects; callers must protect it and avoid logging.
    pub fn read_attributes(&self, types: &[AttributeType]) -> Result<AttributeValues, Error> {
        self.session.validate()?;
        self.session
            .raw()?
            .get_attributes(self.handle, types)
            .map(AttributeValues)
            .map_err(|e| self.session.failed("read attributes", e))
    }
}

/// Attribute data with redacted Debug; values require explicit access.
pub struct AttributeValues(Vec<Attribute>);
impl AttributeValues {
    /// Explicit access to cryptoki values. Their own Debug may reveal secret material.
    pub fn expose_values(&self) -> &[Attribute] {
        &self.0
    }
}
impl fmt::Debug for AttributeValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttributeValues")
            .field(
                "types",
                &self
                    .0
                    .iter()
                    .map(Attribute::attribute_type)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}
fn object_type(class: ObjectClass) -> Option<ObjectType> {
    match class {
        ObjectClass::PUBLIC_KEY => Some(ObjectType::Public),
        ObjectClass::PRIVATE_KEY => Some(ObjectType::Private),
        ObjectClass::CERTIFICATE => Some(ObjectType::Certificate),
        ObjectClass::SECRET_KEY => Some(ObjectType::SecretKey),
        ObjectClass::DATA => Some(ObjectType::Data),
        _ => None,
    }
}
fn object_class(kind: ObjectType) -> Option<ObjectClass> {
    match kind {
        ObjectType::Public => Some(ObjectClass::PUBLIC_KEY),
        ObjectType::Private => Some(ObjectClass::PRIVATE_KEY),
        ObjectType::Certificate => Some(ObjectClass::CERTIFICATE),
        ObjectType::SecretKey => Some(ObjectClass::SECRET_KEY),
        ObjectType::Data => Some(ObjectClass::DATA),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn references_are_identity_only_and_preserve_binary_ids() {
        let reference =
            ObjectRef::new("pkcs11:token=prod;id=%00%FF;type=private".parse().unwrap()).unwrap();
        assert!(reference.template().contains(&Attribute::Id(vec![0, 255])));
        assert!(reference.template().contains(&Attribute::Token(true)));
        for s in [
            "pkcs11:",
            "pkcs11:token=prod",
            "pkcs11:id=1",
            "pkcs11:token=prod;id=1;slot-id=2",
            "pkcs11:token=prod;id=1?vendor=a",
            "pkcs11:token=prod;id=1?pin-value=canary",
            "pkcs11:token=prod;id=1;vendor=x",
        ] {
            assert!(matches!(
                ObjectRef::new(s.parse().unwrap()),
                Err(Error::InvalidObjectReference)
            ));
        }
    }
    #[test]
    fn authentication_and_attribute_debug_do_not_expose_secrets() {
        let pin = SecretString::from("canary");
        assert!(!format!("{:?}", Authentication::User(Pin::Value(&pin))).contains("canary"));
        let attrs = AttributeValues(vec![Attribute::Value(b"canary".to_vec())]);
        assert!(!format!("{attrs:?}").contains(&format!("{:?}", b"canary".to_vec())));
        assert_eq!(
            attrs.expose_values(),
            &[Attribute::Value(b"canary".to_vec())]
        );
    }
}
