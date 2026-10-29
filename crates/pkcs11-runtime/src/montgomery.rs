// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared bounded RFC 8410 Montgomery metadata and native agreement checks.
use crate::{
    Attribute, AttributeInfo, AttributeType as A, Error, KeyType, MechanismType, Object,
    ObjectClass, ObjectRef, Session, SessionMode,
};
use cryptoki::{
    context::Function,
    mechanism::{
        Mechanism,
        elliptic_curve::{EcKdf, Ecdh1DeriveParams},
    },
};
const ATTRIBUTE_LIMIT: usize = 4096;
#[derive(Clone, Copy)]
pub(crate) enum Curve {
    X25519,
    X448,
}
impl Curve {
    pub(crate) const fn parameters(self) -> &'static [u8] {
        match self {
            Self::X25519 => &[6, 3, 43, 101, 110],
            Self::X448 => &[6, 3, 43, 101, 111],
        }
    }
    fn bits(self) -> usize {
        match self {
            Self::X25519 => 255,
            Self::X448 => 448,
        }
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
                "Montgomery attribute changed during read",
            )),
        Some(AttributeInfo::TypeInvalid) if optional => Ok(None),
        _ => Err(Error::MissingMetadata("Montgomery key attribute")),
    }
}
fn parameters(object: &Object<'_, '_>, class: ObjectClass, curve: Curve) -> Result<(), Error> {
    if !matches!(attribute(object, A::Class, false)?, Some(Attribute::Class(v)) if v == class)
        || !matches!(
            attribute(object, A::KeyType, false)?,
            Some(Attribute::KeyType(KeyType::EC_MONTGOMERY))
        )
        || !matches!(attribute(object, A::EcParams, false)?, Some(Attribute::EcParams(v)) if v == curve.parameters())
    {
        return Err(Error::UnsupportedKeyOperation);
    }
    Ok(())
}

pub(crate) fn public_key(
    session: &mut Session<'_>,
    key: &ObjectRef,
    curve: Curve,
) -> Result<Vec<u8>, Error> {
    let object = session.resolve_bounded(key, ATTRIBUTE_LIMIT)?;
    parameters(&object, ObjectClass::PUBLIC_KEY, curve)?;
    match attribute(&object, A::EcPoint, false)? {
        Some(Attribute::EcPoint(bytes)) => Ok(bytes),
        _ => Err(Error::MissingMetadata("Montgomery public point")),
    }
}
pub(crate) struct Derivation<'a> {
    pub curve: Curve,
    pub peer: &'a [u8],
    pub kdf: EcKdf<'a>,
    pub id: &'a [u8],
    pub label: &'a [u8],
    pub length: usize,
    pub aes: bool,
}
pub(crate) fn derive(
    session: &mut Session<'_>,
    base: &ObjectRef,
    request: Derivation<'_>,
) -> Result<(), Error> {
    session.validate()?;
    if session.mode != SessionMode::ReadWrite {
        return Err(Error::ReadWriteRequired);
    }
    let mut template = session.new_secret_template(request.id, request.label, request.aes)?;
    template.push(Attribute::ValueLen(
        request
            .length
            .try_into()
            .map_err(|_| Error::InvalidParameters("Montgomery output length"))?,
    ));
    let object = session.resolve_bounded(base, ATTRIBUTE_LIMIT)?;
    parameters(&object, ObjectClass::PRIVATE_KEY, request.curve)?;
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
    if !info.derive()
        || !(info.min_key_size()..=info.max_key_size()).contains(&request.curve.bits())
    {
        return Err(Error::UnsupportedKeyOperation);
    }
    let mechanism = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(request.kdf, request.peer));
    object
        .session
        .write_operation("derive Montgomery key", |raw| {
            raw.derive_key(&mechanism, object.handle, &template)
        })?;
    Ok(())
}
