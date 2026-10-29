// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeInfo, AttributeType as A, Error, KeyType, MechanismType, Object,
    ObjectClass, ObjectRef, Session, SessionMode, key_operations::validate_secret_identity,
};
use cryptoki::{
    context::Function,
    mechanism::{
        Mechanism,
        elliptic_curve::{EcKdf, Ecdh1DeriveParams},
    },
};
use curve25519_dalek::montgomery::MontgomeryPoint;

const ATTRIBUTE_LIMIT: usize = 4096;
const PARAMETERS: &[u8] = &[6, 3, 43, 101, 110];

/// RFC 7748 public input checked for exact length and noncontributory points.
/// Contains public bytes only; it does not authenticate a peer. High-bit and
/// noncanonical field encodings follow RFC 7748 and are preserved for the token.
#[derive(Clone, PartialEq, Eq)]
pub struct X25519PublicKey([u8; 32]);
impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X25519PublicKey([REDACTED])")
    }
}
impl X25519PublicKey {
    /// Validate public input without using a token or any private key. Reject
    /// points which produce all-zero output with a clamped scalar, including
    /// their RFC 7748 encoding aliases. No agreement secret is computed here.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let raw: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKeyOutput)?;
        // The fixed, public probe scalar becomes 2^254 after clamping. On either
        // the curve or its twist it annihilates exactly the small-order points.
        if MontgomeryPoint(raw).mul_clamped([0; 32]).to_bytes() == [0; 32] {
            return Err(Error::InvalidKeyOutput);
        }
        Ok(Self(raw))
    }
    /// Original little-endian public input, without ASN.1 wrapping.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive a complete 32-byte X25519 secret using CKD_NULL. The persistent output
/// is private, sensitive, nonextractable and permits further derivation only.
pub struct X25519Derivation<'a> {
    /// Length-checked, noncontributory-input-checked peer key.
    pub peer: &'a X25519PublicKey,
    /// Nonempty new secret ID, at most 128 bytes; existing IDs are rejected.
    pub id: &'a [u8],
    /// Nonempty label, at most 128 bytes.
    pub label: &'a [u8],
}
impl X25519Derivation<'_> {
    /// Validate output identity bounds without provider calls.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)
    }
}
impl std::fmt::Debug for X25519Derivation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X25519Derivation([REDACTED])")
    }
}

fn attribute(object: &Object<'_, '_>, kind: A, optional: bool) -> Result<Option<Attribute>, Error> {
    match object.attribute_info(&[kind])?.first() {
        Some(AttributeInfo::Available(_)) => object
            .read_attributes_bounded(&[kind], ATTRIBUTE_LIMIT)?
            .expose_values()
            .first()
            .cloned()
            .map(Some)
            .ok_or(Error::MissingMetadata(
                "X25519 attribute changed during read",
            )),
        Some(AttributeInfo::TypeInvalid) if optional => Ok(None),
        _ => Err(Error::MissingMetadata("X25519 key attribute")),
    }
}
fn parameters(object: &Object<'_, '_>, class: ObjectClass) -> Result<(), Error> {
    if !matches!(attribute(object, A::Class, false)?, Some(Attribute::Class(v)) if v == class)
        || !matches!(
            attribute(object, A::KeyType, false)?,
            Some(Attribute::KeyType(KeyType::EC_MONTGOMERY))
        )
        || !matches!(attribute(object, A::EcParams, false)?, Some(Attribute::EcParams(v)) if v == PARAMETERS)
    {
        return Err(Error::UnsupportedKeyOperation);
    }
    Ok(())
}

impl Session<'_> {
    /// Read an RFC 8410 id-X25519 public key. Requires CKK_EC_MONTGOMERY and
    /// OID-form CKA_EC_PARAMS; curveName, Edwards keys, X448 and DER-wrapped points
    /// are outside this profile. Metadata and identity reads are bounded.
    pub fn x25519_public_key(&mut self, key: &ObjectRef) -> Result<X25519PublicKey, Error> {
        let object = self.resolve_bounded(key, ATTRIBUTE_LIMIT)?;
        parameters(&object, ObjectClass::PUBLIC_KEY)?;
        match attribute(&object, A::EcPoint, false)? {
            Some(Attribute::EcPoint(bytes)) => X25519PublicKey::from_bytes(&bytes),
            _ => Err(Error::MissingMetadata("X25519 public point")),
        }
    }
    /// Derive once with CKM_ECDH1_DERIVE/CKD_NULL from an existing RFC 8410
    /// id-X25519 private key. Requires RW mode, sensitive/nonextractable private
    /// storage, derivation permission, no always-authenticate requirement and an
    /// allowed mechanism. The complete raw result stays on the token for HKDF.
    /// No fallback or retry occurs; failures may leave persistent objects.
    /// This does not authenticate the peer. Check session closure on every result.
    pub fn derive_x25519_secret(
        &mut self,
        base: &ObjectRef,
        request: &X25519Derivation<'_>,
    ) -> Result<(), Error> {
        request.validate()?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        let mut template = self.new_secret_template(request.id, request.label, false)?;
        template.push(Attribute::ValueLen(32.into()));
        let object = self.resolve_bounded(base, ATTRIBUTE_LIMIT)?;
        parameters(&object, ObjectClass::PRIVATE_KEY)?;
        for (kind, expected) in [
            (A::Private, Attribute::Private(true)),
            (A::Sensitive, Attribute::Sensitive(true)),
            (A::Extractable, Attribute::Extractable(false)),
            (A::Derive, Attribute::Derive(true)),
            (A::AlwaysAuthenticate, Attribute::AlwaysAuthenticate(false)),
        ] {
            if attribute(&object, kind, false)? != Some(expected) {
                return Err(Error::UnsupportedKeyOperation);
            }
        }
        let mechanism = MechanismType::ECDH1_DERIVE;
        if let Some(Attribute::AllowedMechanisms(allowed)) =
            attribute(&object, A::AllowedMechanisms, true)?
        {
            if !allowed.is_empty() && !allowed.contains(&mechanism) {
                return Err(Error::UnsupportedKeyOperation);
            }
        }
        let token = object.session.token();
        if !token.module.raw()?.is_fn_supported(Function::DeriveKey)
            || !token.mechanisms()?.contains(&mechanism)
        {
            return Err(Error::UnsupportedKeyOperation);
        }
        let info = token.mechanism_info(mechanism)?;
        if !info.derive() || !(info.min_key_size()..=info.max_key_size()).contains(&255) {
            return Err(Error::UnsupportedKeyOperation);
        }
        let mechanism = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(
            EcKdf::null(),
            request.peer.as_bytes(),
        ));
        object
            .session
            .write_operation("derive X25519 secret", |raw| {
                raw.derive_key(&mechanism, object.handle, &template)
            })?;
        Ok(())
    }
}
