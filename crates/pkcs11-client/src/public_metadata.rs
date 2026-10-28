// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded public metadata, independent of interface-version advertisement.
use crate::{
    Attribute, AttributeInfo, AttributeRead, AttributeType as A, Error, ManagementSession,
    ObjectClass as C, ObjectRef,
};
use pkcs11_runtime::Object;
use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoOwned};

/// Per-attribute bound for public metadata reads, including SPKI DER and text.
pub const PUBLIC_METADATA_MAX_ATTRIBUTE: usize = 65_536;

/// Attribute names used by public metadata inspection. URI values are returned
/// as metadata only; callers must not fetch them implicitly. No secret values,
/// nested templates, or key components are requested by this inspection profile.
pub const PUBLIC_METADATA_FIELDS: &[(A, &str)] = &[
    (A::Class, "class"),
    (A::Label, "label"),
    (A::Id, "id"),
    (A::Token, "token"),
    (A::Private, "private"),
    (A::UniqueId, "unique-id"),
    (A::KeyType, "key-type"),
    (A::CertificateType, "certificate-type"),
    (A::PublicKeyInfo, "public-key-info"),
    (A::ObjectValidationFlags, "object-validation-flags"),
    (A::ProfileId, "profile-id"),
    (A::ValidationType, "validation-type"),
    (A::ValidationVersion, "validation-version"),
    (A::ValidationLevel, "validation-level"),
    (A::ValidationModuleId, "validation-module-id"),
    (A::ValidationFlag, "validation-flag"),
    (A::ValidationAuthorityType, "validation-authority-type"),
    (A::ValidationCountry, "validation-country"),
    (
        A::ValidationCertificateIdentifier,
        "validation-certificate-identifier",
    ),
    (A::ValidationCertificateUri, "validation-certificate-uri"),
    (A::ValidationVendorUri, "validation-vendor-uri"),
    (A::ValidationProfile, "validation-profile"),
];

fn read(object: &Object<'_, '_>, kind: A) -> Result<AttributeRead, Error> {
    let status = object
        .attribute_info(&[kind])?
        .into_iter()
        .next()
        .ok_or(Error::MissingAttributeStatus)?;
    let values = if matches!(status, AttributeInfo::Available(_)) {
        Some(object.read_attributes_bounded(&[kind], PUBLIC_METADATA_MAX_ATTRIBUTE)?)
    } else {
        None
    };
    if kind == A::PublicKeyInfo {
        if let Some(values) = &values {
            for value in values.expose_values() {
                if let Attribute::PublicKeyInfo(der) = value {
                    if !der.is_empty() {
                        SubjectPublicKeyInfoOwned::from_der(der)
                            .map_err(|_| Error::InvalidPublicKey)?;
                    }
                }
            }
        }
    }
    Ok(AttributeRead {
        kind,
        status,
        values,
    })
}

fn metadata(object: &Object<'_, '_>, detailed: bool) -> Result<Vec<AttributeRead>, Error> {
    let class = read(object, A::Class)?;
    let kind = class.values.as_ref().and_then(|v| {
        v.expose_values().iter().find_map(|a| match a {
            Attribute::Class(c) => Some(*c),
            _ => None,
        })
    });
    let mut reads = vec![class];
    if !detailed && !matches!(kind, Some(C::PROFILE | C::VALIDATION)) {
        for attribute in [A::Label, A::Id] {
            reads.push(read(object, attribute)?);
        }
        return Ok(reads);
    }
    for &(attribute, _) in &PUBLIC_METADATA_FIELDS[1..] {
        let applicable = match attribute {
            A::Label | A::Id | A::Token | A::Private | A::UniqueId => true,
            A::KeyType | A::PublicKeyInfo | A::ObjectValidationFlags => {
                matches!(kind, Some(C::PUBLIC_KEY | C::PRIVATE_KEY | C::SECRET_KEY))
            }
            A::CertificateType => kind == Some(C::CERTIFICATE),
            A::ProfileId => kind == Some(C::PROFILE),
            _ => kind == Some(C::VALIDATION),
        };
        if applicable {
            reads.push(read(object, attribute)?);
        }
    }
    Ok(reads)
}

impl ManagementSession<'_> {
    /// Read a bounded public metadata profile for one uniquely resolved RFC 7512
    /// object. Optional fields are queried regardless of selected table version.
    /// Nonempty public-key-info must be SPKI DER; unknown algorithms are allowed
    /// for inspection and do not acquire typed execution support.
    pub fn public_metadata(&mut self, reference: &ObjectRef) -> Result<Vec<AttributeRead>, Error> {
        metadata(&self.session.resolve(reference)?, true)
    }
    /// Inspect public metadata of every visible persistent object, including
    /// profile/validation objects that have no RFC 7512 selector. Handles never
    /// escape this call. Attribute availability is retained; empty values are
    /// available. Scalar/length and provider errors propagate. These reports do
    /// not establish trust or independent validation. URI metadata is never fetched.
    pub fn public_object_metadata(&mut self) -> Result<Vec<Vec<AttributeRead>>, Error> {
        self.session
            .find_objects(&[Attribute::Token(true)])?
            .iter()
            .map(|object| metadata(object, true))
            .collect()
    }
    /// Read bounded class/label/ID summaries, with public metadata snapshots for
    /// profile/validation objects that have no RFC 7512 selector. Ordinary keys
    /// and other objects defer optional metadata to `public_metadata` on selection.
    pub fn public_object_summaries(&mut self) -> Result<Vec<Vec<AttributeRead>>, Error> {
        self.session
            .find_objects(&[Attribute::Token(true)])?
            .iter()
            .map(|object| metadata(object, false))
            .collect()
    }
}
