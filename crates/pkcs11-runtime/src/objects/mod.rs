// SPDX-License-Identifier: MIT OR Apache-2.0
mod attributes;
mod metadata;
mod references;

use std::fmt;

use cryptoki::object::ObjectHandle;
use pkcs11_locator::{ObjectIdentity, ObjectType};

use crate::{
    Attribute, AttributeInfo, AttributeType, Error, ObjectClass, Session,
    error::{backend, unique},
};

pub use attributes::AttributeValues;
pub use metadata::{KeyKind, NamedCurve, PublicKeyMetadata};
pub use references::{CertificateRef, ObjectRef, PrivateKeyRef, PublicKeyRef};

pub(crate) use attributes::{attribute, key_permission};
pub(crate) use metadata::key_kind;

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
            .map(AttributeValues::new)
            .map_err(|e| self.session.failed("read attributes", e))
    }
}

impl<'m> Session<'m> {
    /// Create an object from an explicit template. Template data may contain secrets.
    /// Persistence, privacy and sensitivity are chosen by the caller's template.
    pub fn create_object(&mut self, template: &[Attribute]) -> Result<Object<'_, 'm>, Error> {
        let handle = self.write_operation("create object", |raw| raw.create_object(template))?;
        Ok(Object {
            session: self,
            handle,
        })
    }

    fn find_handles(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>, Error> {
        self.validate()?;
        let raw = self.begin_operation()?;
        let handles = raw
            .find_objects(template)
            .map_err(|e| backend("find objects", e))?;
        self.healthy.set(true);
        Ok(handles)
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
            .token()
            .matches_location(reference.uri())
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
                && reference.uri().object_selector().matches(&identity)
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

impl Object<'_, '_> {
    /// Update explicit attributes once. Provider failures may have partial effects.
    /// The session is invalidated on failure; no rollback or retry is attempted.
    pub fn update_attributes(&mut self, template: &[Attribute]) -> Result<(), Error> {
        self.session.write_operation("update attributes", |raw| {
            raw.update_attributes(self.handle, template)
        })
    }
    /// Destroy this selected object once. Consumes the session-bound wrapper.
    pub fn destroy(self) -> Result<(), Error> {
        self.session
            .write_operation("destroy object", |raw| raw.destroy_object(self.handle))
    }
}
