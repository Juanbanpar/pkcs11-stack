// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared bounded Montgomery metadata and native agreement checks.
use crate::{
    Attribute, AttributeInfo, AttributeType as A, Error, KeyType, MechanismType, Object,
    ObjectClass, ObjectRef, Session, SessionMode, Token, key_operations::validate_secret_identity,
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
    Curve25519,
    Curve448,
}
impl Curve {
    pub(crate) const fn parameters(self) -> &'static [u8] {
        match self {
            Self::X25519 => &[6, 3, 43, 101, 110],
            Self::X448 => &[6, 3, 43, 101, 111],
            Self::Curve25519 => b"\x13\x0acurve25519",
            Self::Curve448 => b"\x13\x08curve448",
        }
    }
    fn bits(self) -> usize {
        match self {
            Self::X25519 | Self::Curve25519 => 255,
            Self::X448 | Self::Curve448 => 448,
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

pub(crate) fn generation_supported(token: &Token<'_>, curve: Curve) -> Result<bool, Error> {
    let mechanism = MechanismType::ECC_MONTGOMERY_KEY_PAIR_GEN;
    if !token
        .module
        .raw()?
        .is_fn_supported(Function::GenerateKeyPair)
        || !token.mechanisms()?.contains(&mechanism)
    {
        return Ok(false);
    }
    let info = token.mechanism_info(mechanism)?;
    Ok(info.generate_key_pair()
        && (info.min_key_size()..=info.max_key_size()).contains(&curve.bits()))
}

pub(crate) fn generate<'s, 'm>(
    session: &'s mut Session<'m>,
    curve: Curve,
    id: &[u8],
    label: &[u8],
) -> Result<(Object<'s, 'm>, Object<'s, 'm>), Error> {
    validate_secret_identity(id, label)?;
    session.validate()?;
    if session.mode != SessionMode::ReadWrite {
        return Err(Error::ReadWriteRequired);
    }
    if !generation_supported(session.token(), curve)? {
        return Err(Error::UnsupportedKeyOperation);
    }
    for class in [ObjectClass::PUBLIC_KEY, ObjectClass::PRIVATE_KEY] {
        if !session
            .find_objects(&[
                Attribute::Token(true),
                Attribute::Class(class),
                Attribute::Id(id.to_vec()),
            ])?
            .is_empty()
        {
            return Err(Error::InvalidParameters("key pair ID already exists"));
        }
    }
    let public = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Id(id.to_vec()),
        Attribute::Label(label.to_vec()),
        Attribute::EcParams(curve.parameters().to_vec()),
        Attribute::Verify(false),
        Attribute::VerifyRecover(false),
        Attribute::Encrypt(false),
        Attribute::Wrap(false),
        Attribute::Derive(false),
    ];
    let private = [
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Id(id.to_vec()),
        Attribute::Label(label.to_vec()),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Derive(true),
        Attribute::Sign(false),
        Attribute::SignRecover(false),
        Attribute::Decrypt(false),
        Attribute::Unwrap(false),
        Attribute::AlwaysAuthenticate(false),
        Attribute::AllowedMechanisms(vec![MechanismType::ECDH1_DERIVE]),
    ];
    let (public, private) = session.write_operation("generate Montgomery key pair", |raw| {
        raw.generate_key_pair(&Mechanism::EccMontgomeryKeyPairGen, &public, &private)
    })?;
    Ok((
        Object {
            session,
            handle: public,
        },
        Object {
            session,
            handle: private,
        },
    ))
}

pub(crate) fn import_public<'s, 'm>(
    session: &'s mut Session<'m>,
    curve: Curve,
    key: &[u8],
    id: &[u8],
    label: &[u8],
) -> Result<Object<'s, 'm>, Error> {
    validate_secret_identity(id, label)?;
    session.validate()?;
    if session.mode != SessionMode::ReadWrite {
        return Err(Error::ReadWriteRequired);
    }
    if !session
        .token()
        .module
        .raw()?
        .is_fn_supported(Function::CreateObject)
    {
        return Err(Error::UnsupportedKeyOperation);
    }
    if !session
        .find_objects(&[
            Attribute::Token(true),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Id(id.to_vec()),
        ])?
        .is_empty()
    {
        return Err(Error::InvalidParameters("public key ID already exists"));
    }
    session.create_object(&[
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::EC_MONTGOMERY),
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Id(id.to_vec()),
        Attribute::Label(label.to_vec()),
        Attribute::EcParams(curve.parameters().to_vec()),
        Attribute::EcPoint(key.to_vec()),
        Attribute::Verify(false),
        Attribute::VerifyRecover(false),
        Attribute::Encrypt(false),
        Attribute::Wrap(false),
        Attribute::Derive(false),
    ])
}
