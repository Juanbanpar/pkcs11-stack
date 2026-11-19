// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeType, Error, KeyKind, MechanismType, NamedCurve, Object, ObjectClass,
    ObjectRef, Session,
    capability::check_key_mechanism,
    objects::{attribute, key_kind, key_permission},
};
use cryptoki::mechanism::{
    Mechanism,
    elliptic_curve::{EcKdf, Ecdh1DeriveParams},
};

/// Explicit parameters for raw ECDH generic-secret creation. Debug omits all input.
pub struct EcdhDerivation<'a> {
    /// Named curve shared by base and peer keys.
    pub curve: NamedCurve,
    /// Validated uncompressed SEC1 peer point.
    pub peer: &'a [u8],
    /// New nonempty secret key ID, bounded to 128 bytes.
    pub id: &'a [u8],
    /// New nonempty label, bounded to 128 bytes.
    pub label: &'a [u8],
}
impl std::fmt::Debug for EcdhDerivation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EcdhDerivation([REDACTED])")
    }
}

pub(crate) fn ecdh_curve(object: &Object<'_, '_>) -> Result<NamedCurve, Error> {
    if !key_permission(object, AttributeType::Derive)? {
        return Err(Error::UnsupportedKeyOperation);
    }
    if !matches!(
        attribute(object, AttributeType::Class, true)?,
        Some(Attribute::Class(ObjectClass::PRIVATE_KEY))
    ) || !matches!(
        attribute(object, AttributeType::AlwaysAuthenticate, true)?,
        Some(Attribute::AlwaysAuthenticate(false))
    ) {
        return Err(Error::UnsupportedKeyOperation);
    }
    let KeyKind::Ec(curve) = key_kind(object)? else {
        return Err(Error::UnsupportedKeyOperation);
    };
    // EC mechanism bounds are in bits.
    check_key_mechanism(object, MechanismType::ECDH1_DERIVE, curve.bits(), |info| {
        info.derive()
    })?;
    Ok(curve)
}

impl Session<'_> {
    /// Derive a persistent raw ECDH generic secret using the explicitly selected null KDF.
    /// Encryption, decryption and transfer permissions are disabled; only derivation is allowed.
    /// The caller must validate the peer point on the selected curve before calling.
    /// No key bytes leave the provider. Failures can have persistent effects; no retry.
    pub fn derive_ecdh_secret(
        &mut self,
        base: &ObjectRef,
        request: &EcdhDerivation<'_>,
    ) -> Result<(), Error> {
        let EcdhDerivation {
            curve,
            peer,
            id,
            label,
        } = *request;
        let mut template = self.new_secret_template(id, label, false)?;
        if peer.first() != Some(&4)
            || peer.len()
                != match curve {
                    NamedCurve::P256 => 65,
                    NamedCurve::P384 => 97,
                    NamedCurve::P521 => 133,
                }
        {
            return Err(Error::InvalidParameters("ECDH peer"));
        }
        template.push(Attribute::ValueLen(
            (match curve {
                NamedCurve::P256 => 32,
                NamedCurve::P384 => 48,
                NamedCurve::P521 => 66,
            })
            .into(),
        ));
        let object = self.resolve(base)?;
        if ecdh_curve(&object)? != curve {
            return Err(Error::UnsupportedKeyOperation);
        }
        let mechanism = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), peer));
        object
            .session
            .write_operation("derive ECDH secret", |raw| {
                raw.derive_key(&mechanism, object.handle, &template)
            })?;
        Ok(())
    }
}
