// SPDX-License-Identifier: MIT OR Apache-2.0
use cryptoki::object::KeyType;

use crate::{Attribute, AttributeType, Error, Object, PrivateKeyRef, PublicKeyRef, Session};

use super::attribute;

/// Supported named prime curves. Unknown/explicit parameters fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedCurve {
    /// NIST P-256.
    P256,
    /// NIST P-384.
    P384,
    /// NIST P-521.
    P521,
}
impl NamedCurve {
    /// Order bit size, used for key bounds and signature width.
    pub fn bits(self) -> usize {
        match self {
            Self::P256 => 256,
            Self::P384 => 384,
            Self::P521 => 521,
        }
    }
    fn from_der(der: &[u8]) -> Result<Self, Error> {
        match der {
            [6, 8, 42, 134, 72, 206, 61, 3, 1, 7] => Ok(Self::P256),
            [6, 5, 43, 129, 4, 0, 34] => Ok(Self::P384),
            [6, 5, 43, 129, 4, 0, 35] => Ok(Self::P521),
            _ => Err(Error::UnsupportedSigning("unknown EC parameters")),
        }
    }
}
/// Public key characteristics obtained from key attributes, never certificate labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// RSA with the observed modulus bit length.
    Rsa {
        /// Modulus size.
        bits: usize,
    },
    /// EC with a recognized named curve.
    Ec(NamedCurve),
    /// Edwards curve used by EdDSA.
    Edwards(crate::EdDsaCurve),
    /// Montgomery curve used by X25519/X448.
    Montgomery(crate::MontgomeryCurve),
}
impl KeyKind {
    /// Key size or field size in bits.
    pub fn bits(self) -> usize {
        match self {
            Self::Rsa { bits } => bits,
            Self::Ec(curve) => curve.bits(),
            Self::Edwards(curve) => curve.bits(),
            Self::Montgomery(curve) => curve.bits(),
        }
    }
}
pub(crate) fn key_kind(object: &Object<'_, '_>) -> Result<KeyKind, Error> {
    match attribute(object, AttributeType::KeyType, true)? {
        Some(Attribute::KeyType(KeyType::RSA)) => {
            match attribute(object, AttributeType::Modulus, true)? {
                Some(Attribute::Modulus(value)) => {
                    let significant = value
                        .iter()
                        .position(|&b| b != 0)
                        .ok_or(Error::MissingMetadata("zero RSA modulus"))?;
                    let bits = (value.len() - significant) * 8
                        - value[significant].leading_zeros() as usize;
                    Ok(KeyKind::Rsa { bits })
                }
                _ => Err(Error::MissingMetadata("RSA modulus")),
            }
        }
        Some(Attribute::KeyType(KeyType::EC)) => {
            match attribute(object, AttributeType::EcParams, true)? {
                Some(Attribute::EcParams(value)) => Ok(KeyKind::Ec(NamedCurve::from_der(&value)?)),
                _ => Err(Error::MissingMetadata("EC parameters")),
            }
        }
        Some(Attribute::KeyType(KeyType::EC_EDWARDS)) => {
            match attribute(object, AttributeType::EcParams, true)? {
                Some(Attribute::EcParams(value)) => {
                    Ok(KeyKind::Edwards(crate::EdDsaCurve::from_ec_params(&value)?))
                }
                _ => Err(Error::MissingMetadata("EdDSA curve parameters")),
            }
        }
        _ => Err(Error::UnsupportedSigning("key type")),
    }
}
/// Public attributes only; no private scalar, exponent or secret value is read.
/// Optional fields reflect token storage differences and may be absent.
#[derive(Debug, Clone)]
pub struct PublicKeyMetadata {
    /// Key type and public size/curve.
    pub key: KeyKind,
    /// Token-provided DER SubjectPublicKeyInfo, if supported and nonempty.
    pub spki: Option<Vec<u8>>,
    /// Unsigned big-endian RSA modulus.
    pub modulus: Option<Vec<u8>>,
    /// Unsigned big-endian RSA public exponent.
    pub public_exponent: Option<Vec<u8>>,
    /// DER EC parameters.
    pub ec_params: Option<Vec<u8>>,
    /// Token EC point attribute, retaining its PKCS#11 OCTET STRING encoding.
    pub ec_point: Option<Vec<u8>>,
}
fn public_metadata(object: &Object<'_, '_>) -> Result<PublicKeyMetadata, Error> {
    let key = key_kind(object)?;
    let spki = match attribute(object, AttributeType::PublicKeyInfo, false)? {
        Some(Attribute::PublicKeyInfo(v)) if !v.is_empty() => Some(v),
        _ => None,
    };
    let mut result = PublicKeyMetadata {
        key,
        spki,
        modulus: None,
        public_exponent: None,
        ec_params: None,
        ec_point: None,
    };
    match key {
        KeyKind::Rsa { .. } => {
            if let Some(Attribute::Modulus(v)) = attribute(object, AttributeType::Modulus, true)? {
                result.modulus = Some(v);
            }
            if let Some(Attribute::PublicExponent(v)) =
                attribute(object, AttributeType::PublicExponent, false)?
            {
                result.public_exponent = Some(v);
            }
        }
        KeyKind::Ec(_) | KeyKind::Edwards(_) | KeyKind::Montgomery(_) => {
            if let Some(Attribute::EcParams(v)) = attribute(object, AttributeType::EcParams, true)?
            {
                result.ec_params = Some(v);
            }
            if let Some(Attribute::EcPoint(v)) = attribute(object, AttributeType::EcPoint, false)? {
                result.ec_point = Some(v);
            }
        }
    }
    Ok(result)
}
impl PrivateKeyRef {
    /// Read only public attributes of this private key, using the caller's session.
    pub fn public_metadata(&self, session: &mut Session<'_>) -> Result<PublicKeyMetadata, Error> {
        public_metadata(&session.resolve(self.as_object_ref())?)
    }
}
impl PublicKeyRef {
    /// Read public material from an independently selected public object.
    pub fn public_metadata(&self, session: &mut Session<'_>) -> Result<PublicKeyMetadata, Error> {
        public_metadata(&session.resolve(self.as_object_ref())?)
    }
}
