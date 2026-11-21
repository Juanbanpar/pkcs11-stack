// SPDX-License-Identifier: MIT OR Apache-2.0
use pkcs11_locator::{ObjectType, Pkcs11Uri};

use crate::{Attribute, AttributeType, Error, ObjectClass, Session};

use super::attribute;

/// A persistent, secret-free locator, never a PKCS#11 handle.
///
/// [`Session::resolve`] checks that exactly one object matches. Prefer a token
/// serial and binary object ID. Persistent URI criteria can still match a
/// replacement object.
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
    pub(super) fn template(&self) -> Vec<Attribute> {
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
            && let Some(class) = object_class(kind)
        {
            template.push(Attribute::Class(class));
        }
        template
    }
}

macro_rules! reference {
    ($name:ident, $kind:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name(ObjectRef);
        impl $name {
            /// Require an explicit object class and stable token/object constraints.
            pub fn new(uri: Pkcs11Uri) -> Result<Self, Error> {
                if uri.path_attribute("type") != Some($kind.as_bytes()) {
                    return Err(Error::InvalidObjectReference);
                }
                Ok(Self(ObjectRef::new(uri)?))
            }
            /// Borrow the underlying secret-free persistent reference.
            pub fn as_object_ref(&self) -> &ObjectRef {
                &self.0
            }
        }
    };
}
reference!(
    PrivateKeyRef,
    "private",
    "Persistent private-key selector, with no cached handle or private key material."
);
reference!(
    PublicKeyRef,
    "public",
    "Persistent public-key selector, independently resolved and ambiguity checked."
);
reference!(
    CertificateRef,
    "cert",
    "Persistent certificate selector; association with a key is an application decision."
);

impl CertificateRef {
    /// Read certificate bytes without interpreting trust or assuming key association.
    pub fn der(&self, session: &mut Session<'_>) -> Result<Vec<u8>, Error> {
        match attribute(
            &session.resolve(self.as_object_ref())?,
            AttributeType::Value,
            true,
        )? {
            Some(Attribute::Value(v)) => Ok(v),
            _ => Err(Error::MissingMetadata("certificate value")),
        }
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
}
