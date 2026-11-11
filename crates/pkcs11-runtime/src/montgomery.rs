// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 7748 X25519/X448 key generation and ECDH derivation through published
//! upstream mechanisms.
//!
//! The private key and derived secret stay on the token. Peer public inputs are
//! length- and low-order-checked before use.

use crate::{
    AesKeySize, Attribute, AttributeType, Error, MechanismType, Object, ObjectClass, ObjectRef,
    PublicKeyRef, Session, SessionMode, Token, error::map_function_not_supported,
    key_operations::validate_secret_identity, signing::attribute,
};
use cryptoki::{
    context::Function,
    mechanism::{
        Mechanism,
        elliptic_curve::{EcKdf, Ecdh1DeriveParams},
    },
    object::KeyType,
};

/// RFC 7748 Montgomery curves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MontgomeryCurve {
    /// X25519.
    X25519,
    /// X448.
    X448,
}

impl MontgomeryCurve {
    /// Every curve executable through this module.
    pub const ALL: [Self; 2] = [Self::X25519, Self::X448];

    /// Field size used by PKCS#11 mechanism bounds, in bits.
    pub fn bits(self) -> usize {
        match self {
            Self::X25519 => 255,
            Self::X448 => 448,
        }
    }

    /// Raw public-key and shared-secret length in bytes.
    pub fn public_key_length(self) -> usize {
        match self {
            Self::X25519 => 32,
            Self::X448 => 56,
        }
    }

    /// DER RFC 8410 algorithm OID used by `CKA_EC_PARAMS`.
    pub fn ec_params(self) -> &'static [u8] {
        match self {
            Self::X25519 => &[6, 3, 43, 101, 110],
            Self::X448 => &[6, 3, 43, 101, 111],
        }
    }

    /// Decode an RFC 8410 OID or RFC 8032 curveName.
    pub fn from_ec_params(params: &[u8]) -> Result<Self, Error> {
        match params {
            [6, 3, 43, 101, 110] | b"\x13\x0acurve25519" => Ok(Self::X25519),
            [6, 3, 43, 101, 111] | b"\x13\x08curve448" => Ok(Self::X448),
            _ => Err(Error::UnsupportedKeyOperation),
        }
    }
}

impl std::fmt::Display for MontgomeryCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::X25519 => "x25519",
            Self::X448 => "x448",
        })
    }
}

/// Checked RFC 7748 peer public input. Contains public bytes only.
#[derive(Clone, Debug)]
pub struct MontgomeryPublicKey {
    curve: MontgomeryCurve,
    value: Vec<u8>,
}

impl MontgomeryPublicKey {
    /// Validate length and reject low-order curve/twist points.
    pub fn from_bytes(curve: MontgomeryCurve, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != curve.public_key_length() {
            return Err(Error::InvalidKeyOutput);
        }
        let low_order = match curve {
            MontgomeryCurve::X25519 => {
                let raw: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKeyOutput)?;
                // The fixed public probe scalar becomes 2^254 after clamping.
                curve25519_dalek::montgomery::MontgomeryPoint(raw)
                    .mul_clamped([0; 32])
                    .to_bytes()
                    == [0; 32]
            }
            MontgomeryCurve::X448 => {
                let raw: [u8; 56] = bytes.try_into().map_err(|_| Error::InvalidKeyOutput)?;
                ed448_goldilocks_plus::MontgomeryPoint(raw)
                    .to_projective()
                    .to_affine()
                    .is_low_order()
            }
        };
        if low_order {
            return Err(Error::InvalidKeyOutput);
        }
        Ok(Self {
            curve,
            value: bytes.to_vec(),
        })
    }

    /// Selected curve.
    pub fn curve(&self) -> MontgomeryCurve {
        self.curve
    }

    /// Raw RFC 7748 public bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}

/// ECDH KDF applied to the raw agreement value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MontgomeryKdf {
    /// `CKD_NULL`, complete raw agreement value.
    Null,
    /// ANSI X9.63 SHA-256.
    X963Sha256,
    /// ANSI X9.63 SHA-384.
    X963Sha384,
    /// ANSI X9.63 SHA-512.
    X963Sha512,
    /// NIST SP 800-56A SHA-256.
    Sp80056aSha256,
    /// NIST SP 800-56A SHA-384.
    Sp80056aSha384,
    /// NIST SP 800-56A SHA-512.
    Sp80056aSha512,
}

impl MontgomeryKdf {
    /// Whether this KDF preserves the complete raw agreement value.
    pub fn is_null(self) -> bool {
        matches!(self, Self::Null)
    }

    fn params<'a>(self, shared_info: &'a [u8]) -> EcKdf<'a> {
        match self {
            Self::Null => EcKdf::null(),
            Self::X963Sha256 => EcKdf::sha256(shared_info),
            Self::X963Sha384 => EcKdf::sha384(shared_info),
            Self::X963Sha512 => EcKdf::sha512(shared_info),
            Self::Sp80056aSha256 => EcKdf::sha256_sp800(shared_info),
            Self::Sp80056aSha384 => EcKdf::sha384_sp800(shared_info),
            Self::Sp80056aSha512 => EcKdf::sha512_sp800(shared_info),
        }
    }
}

/// Derived key type and permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MontgomeryOutput {
    /// AES key with encryption/decryption permission only.
    Aes(AesKeySize),
    /// Generic secret permitting only further derivation, 1..=4096 bytes.
    DerivationSecret {
        /// Output length in bytes.
        length: usize,
    },
}

impl MontgomeryOutput {
    /// Output length in bytes.
    pub fn length(self) -> usize {
        match self {
            Self::Aes(size) => size.length(),
            Self::DerivationSecret { length } => length,
        }
    }

    fn aes(self) -> bool {
        matches!(self, Self::Aes(_))
    }
}

/// Bounded Montgomery agreement request.
pub struct MontgomeryDerivation<'a> {
    /// Checked peer public input; the caller must authenticate ownership.
    pub peer: &'a MontgomeryPublicKey,
    /// Explicit KDF.
    pub kdf: MontgomeryKdf,
    /// Public protocol context, at most 4096 bytes; must be empty for null KDF.
    pub shared_info: &'a [u8],
    /// Output type and length.
    pub output: MontgomeryOutput,
    /// New nonempty secret ID, at most 128 bytes.
    pub id: &'a [u8],
    /// New nonempty label, at most 128 bytes.
    pub label: &'a [u8],
}

impl std::fmt::Debug for MontgomeryDerivation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MontgomeryDerivation")
            .field("curve", &self.peer.curve())
            .field("kdf", &self.kdf)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}

impl MontgomeryDerivation<'_> {
    /// Validate identity, context and KDF/output compatibility without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)?;
        if self.shared_info.len() > 4096 {
            return Err(Error::InvalidParameters("Montgomery shared info length"));
        }
        if self.kdf.is_null() {
            if !self.shared_info.is_empty() {
                return Err(Error::InvalidParameters("null KDF with shared info"));
            }
            if self.output.length() != self.peer.curve().public_key_length() {
                return Err(Error::InvalidParameters("raw Montgomery output length"));
            }
        } else if !(1..=4096).contains(&self.output.length()) {
            return Err(Error::InvalidParameters("Montgomery output length"));
        }
        Ok(())
    }
}

/// Advisory Montgomery generation choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MontgomeryCapabilities {
    /// Selected curve.
    pub curve: MontgomeryCurve,
    /// Generation and ECDH derivation are advertised.
    pub can_generate: bool,
    /// Native derive support is advertised.
    pub can_derive: bool,
}

fn curve_of(object: &Object<'_, '_>, class: ObjectClass) -> Result<MontgomeryCurve, Error> {
    if !matches!(
        attribute(object, AttributeType::Class, true)?,
        Some(Attribute::Class(value)) if value == class
    ) || !matches!(
        attribute(object, AttributeType::KeyType, true)?,
        Some(Attribute::KeyType(KeyType::EC_MONTGOMERY))
    ) {
        return Err(Error::UnsupportedKeyOperation);
    }
    match attribute(object, AttributeType::EcParams, true)? {
        Some(Attribute::EcParams(value)) => MontgomeryCurve::from_ec_params(&value),
        _ => Err(Error::MissingMetadata("Montgomery curve parameters")),
    }
}

fn raw_ec_point(value: &[u8], length: usize) -> Option<&[u8]> {
    if value.len() == length {
        Some(value)
    } else if value.len() == length + 2 && value[0] == 0x04 && value[1] as usize == length {
        Some(&value[2..])
    } else {
        None
    }
}

fn size_supported(curve: MontgomeryCurve, minimum: usize, maximum: usize) -> bool {
    // Providers disagree on whether X25519 is reported as 255 or 256 bits.
    // Accept either endpoint while keeping X448 exact.
    match curve {
        MontgomeryCurve::X25519 => minimum <= 256 && maximum >= 255,
        MontgomeryCurve::X448 => minimum <= 448 && maximum >= 448,
    }
}

fn generation_supported(token: &Token<'_>, curve: MontgomeryCurve) -> Result<bool, Error> {
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
    Ok(info.generate_key_pair() && size_supported(curve, info.min_key_size(), info.max_key_size()))
}

fn derivation_supported(token: &Token<'_>, curve: MontgomeryCurve) -> Result<bool, Error> {
    let mechanism = MechanismType::ECDH1_DERIVE;
    if !token.module.raw()?.is_fn_supported(Function::DeriveKey)
        || !token.mechanisms()?.contains(&mechanism)
    {
        return Ok(false);
    }
    let info = token.mechanism_info(mechanism)?;
    Ok(info.derive() && size_supported(curve, info.min_key_size(), info.max_key_size()))
}

impl Token<'_> {
    /// Advertised Montgomery generation and derivation choices.
    pub fn montgomery_capabilities(&self) -> Result<Vec<MontgomeryCapabilities>, Error> {
        let mut result = Vec::new();
        for curve in MontgomeryCurve::ALL {
            let can_generate = generation_supported(self, curve)?;
            let can_derive = derivation_supported(self, curve)?;
            if can_generate || can_derive {
                result.push(MontgomeryCapabilities {
                    curve,
                    can_generate,
                    can_derive,
                });
            }
        }
        Ok(result)
    }
}

impl<'m> Session<'m> {
    /// Generate a persistent Montgomery pair in an RW session.
    pub fn generate_montgomery_key_pair(
        &mut self,
        curve: MontgomeryCurve,
        id: &[u8],
        label: &[u8],
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        validate_secret_identity(id, label)?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        if !generation_supported(self.token(), curve)? {
            return Err(Error::UnsupportedKeyOperation);
        }
        for class in [ObjectClass::PUBLIC_KEY, ObjectClass::PRIVATE_KEY] {
            if !self
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
            Attribute::KeyType(KeyType::EC_MONTGOMERY),
            Attribute::EcParams(curve.ec_params().to_vec()),
            Attribute::Verify(false),
            Attribute::Encrypt(false),
            Attribute::Wrap(false),
            Attribute::Derive(false),
        ];
        let private = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.to_vec()),
            Attribute::KeyType(KeyType::EC_MONTGOMERY),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Derive(true),
            Attribute::Sign(false),
            Attribute::Decrypt(false),
            Attribute::Unwrap(false),
            Attribute::AlwaysAuthenticate(false),
            Attribute::AllowedMechanisms(vec![MechanismType::ECDH1_DERIVE]),
        ];
        let (public, private) = self.write_operation("generate Montgomery key pair", |raw| {
            raw.generate_key_pair(&Mechanism::EccMontgomeryKeyPairGen, &public, &private)
        })?;
        Ok((
            Object {
                session: self,
                handle: public,
            },
            Object {
                session: self,
                handle: private,
            },
        ))
    }

    /// Read the private key's Montgomery curve without reading key bytes.
    pub fn montgomery_private_curve(
        &mut self,
        key: &crate::PrivateKeyRef,
    ) -> Result<MontgomeryCurve, Error> {
        curve_of(
            &self.resolve(key.as_object_ref())?,
            ObjectClass::PRIVATE_KEY,
        )
    }

    /// Read a public Montgomery key as raw RFC 7748 bytes.
    pub fn montgomery_public_key(
        &mut self,
        key: &PublicKeyRef,
    ) -> Result<MontgomeryPublicKey, Error> {
        let object = self.resolve(key.as_object_ref())?;
        let curve = curve_of(&object, ObjectClass::PUBLIC_KEY)?;
        match attribute(&object, AttributeType::EcPoint, true)? {
            Some(Attribute::EcPoint(value)) => {
                match raw_ec_point(&value, curve.public_key_length()) {
                    Some(raw) => MontgomeryPublicKey::from_bytes(curve, raw),
                    None => Err(Error::InvalidKeyOutput),
                }
            }
            _ => Err(Error::InvalidKeyOutput),
        }
    }

    /// Import a checked public Montgomery key for derivation only.
    pub fn import_montgomery_public_key(
        &mut self,
        key: &MontgomeryPublicKey,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        validate_secret_identity(id, label)?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        if !self
            .find_objects(&[
                Attribute::Token(true),
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Id(id.to_vec()),
            ])?
            .is_empty()
        {
            return Err(Error::InvalidParameters("public key ID already exists"));
        }
        self.create_object(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::EC_MONTGOMERY),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.to_vec()),
            Attribute::EcParams(key.curve().ec_params().to_vec()),
            Attribute::EcPoint(key.as_bytes().to_vec()),
            Attribute::Verify(false),
            Attribute::Encrypt(false),
            Attribute::Wrap(false),
            Attribute::Derive(false),
        ])?;
        Ok(())
    }

    /// Derive one persistent key from a Montgomery private key.
    pub fn derive_montgomery(
        &mut self,
        base: &ObjectRef,
        request: &MontgomeryDerivation<'_>,
    ) -> Result<(), Error> {
        request.validate()?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        let mut template =
            self.new_secret_template(request.id, request.label, request.output.aes())?;
        template.push(Attribute::ValueLen(
            request
                .output
                .length()
                .try_into()
                .map_err(|_| Error::InvalidParameters("Montgomery output length"))?,
        ));
        let object = self.resolve(base)?;
        let curve = curve_of(&object, ObjectClass::PRIVATE_KEY)?;
        if curve != request.peer.curve() {
            return Err(Error::UnsupportedKeyOperation);
        }
        for (kind, expected) in [
            (AttributeType::Private, Attribute::Private(true)),
            (AttributeType::Sensitive, Attribute::Sensitive(true)),
            (AttributeType::Extractable, Attribute::Extractable(false)),
            (AttributeType::Derive, Attribute::Derive(true)),
            (
                AttributeType::AlwaysAuthenticate,
                Attribute::AlwaysAuthenticate(false),
            ),
        ] {
            if attribute(&object, kind, true)? != Some(expected) {
                return Err(Error::UnsupportedKeyOperation);
            }
        }
        if !derivation_supported(object.session.token(), curve)? {
            return Err(Error::UnsupportedKeyOperation);
        }
        if let Some(Attribute::AllowedMechanisms(allowed)) =
            attribute(&object, AttributeType::AllowedMechanisms, false)?
        {
            if !allowed.is_empty() && !allowed.contains(&MechanismType::ECDH1_DERIVE) {
                return Err(Error::UnsupportedKeyOperation);
            }
        }
        let mechanism = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(
            request.kdf.params(request.shared_info),
            request.peer.as_bytes(),
        ));
        object
            .session
            .write_operation("derive Montgomery key", |raw| {
                raw.derive_key(&mechanism, object.handle, &template)
            })
            .map_err(|error| map_function_not_supported(error, Error::UnsupportedKeyOperation))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curve_lengths_and_parameter_encodings_are_explicit() {
        for (curve, bits, length, params) in [
            (
                MontgomeryCurve::X25519,
                255,
                32,
                &[6u8, 3, 43, 101, 110][..],
            ),
            (MontgomeryCurve::X448, 448, 56, &[6u8, 3, 43, 101, 111][..]),
        ] {
            assert_eq!(curve.bits(), bits);
            assert_eq!(curve.public_key_length(), length);
            assert_eq!(curve.ec_params(), params);
            assert_eq!(MontgomeryCurve::from_ec_params(params).unwrap(), curve);
        }
        assert!(MontgomeryCurve::from_ec_params(&[6, 3, 43, 101, 112]).is_err());
        assert!(MontgomeryPublicKey::from_bytes(MontgomeryCurve::X25519, &[0; 32]).is_err());
        assert!(MontgomeryPublicKey::from_bytes(MontgomeryCurve::X25519, &[1; 31]).is_err());
    }
}
