// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure RFC 8032 EdDSA (Ed25519/Ed448) through published upstream types.
//!
//! Accepts RFC 8410 OID and RFC 8032 curveName parameters. Prehash/context
//! schemes and per-operation authentication are unsupported.

use crate::{
    Attribute, AttributeType, Error, MechanismType, Object, ObjectClass, Pin, PrivateKeyRef,
    PublicKeyRef, Session, SessionMode, Token,
    error::{backend, function_not_supported, map_function_not_supported},
    key_operations::validate_secret_identity,
    signing::attribute,
};
use cryptoki::{
    error::{Error as CryptokiError, RvError},
    mechanism::{
        Mechanism,
        eddsa::{EddsaParams, EddsaSignatureScheme},
    },
    object::KeyType,
};

/// RFC 8032 Edwards signing curves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EdDsaCurve {
    /// Ed25519.
    Ed25519,
    /// Ed448.
    Ed448,
}

impl EdDsaCurve {
    /// Every curve executable through this module.
    pub const ALL: [Self; 2] = [Self::Ed25519, Self::Ed448];

    /// Field size used by PKCS#11 mechanism bounds, in bits.
    pub fn bits(self) -> usize {
        match self {
            Self::Ed25519 => 255,
            Self::Ed448 => 448,
        }
    }

    /// Raw RFC 8032 public-key length in bytes.
    pub fn public_key_length(self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::Ed448 => 57,
        }
    }

    /// Raw RFC 8032 signature length in bytes.
    pub fn signature_length(self) -> usize {
        self.public_key_length() * 2
    }

    /// DER RFC 8410 algorithm OID used by `CKA_EC_PARAMS`.
    pub fn ec_params(self) -> &'static [u8] {
        match self {
            Self::Ed25519 => &[6, 3, 43, 101, 112],
            Self::Ed448 => &[6, 3, 43, 101, 113],
        }
    }

    /// Decode an RFC 8410 algorithm OID.
    pub fn from_ec_params(params: &[u8]) -> Result<Self, Error> {
        match params {
            [6, 3, 43, 101, 112] | b"\x13\x0cedwards25519" => Ok(Self::Ed25519),
            [6, 3, 43, 101, 113] | b"\x13\x0aedwards448" => Ok(Self::Ed448),
            _ => Err(Error::UnsupportedSigning("EdDSA curve parameters")),
        }
    }

    fn mechanism(self) -> Mechanism<'static> {
        Mechanism::Eddsa(EddsaParams::new(match self {
            Self::Ed25519 => EddsaSignatureScheme::Ed25519,
            Self::Ed448 => EddsaSignatureScheme::Ed448(&[]),
        }))
    }
}

impl std::fmt::Display for EdDsaCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ed25519 => "ed25519",
            Self::Ed448 => "ed448",
        })
    }
}

/// Pure EdDSA request over the original message.
#[derive(Clone, Copy)]
pub struct EdDsaRequest<'a> {
    /// Expected curve, checked against the selected key before execution.
    pub curve: EdDsaCurve,
    /// Original message, including an empty message.
    pub message: &'a [u8],
}

impl std::fmt::Debug for EdDsaRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdDsaRequest")
            .field("curve", &self.curve)
            .finish_non_exhaustive()
    }
}

/// Advisory permissions and curve, rediscovered before execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdDsaCapabilities {
    /// Curve read from `CKA_EC_PARAMS`.
    pub curve: EdDsaCurve,
    /// Private-key permission, allowed mechanisms and native support permit signing.
    pub can_sign: bool,
    /// Public-key permission, allowed mechanisms and native support permit verification.
    pub can_verify: bool,
    /// Context-specific authentication is required after signing initialization.
    pub always_authenticate: bool,
}

/// Length-checked raw RFC 8032 public bytes.
#[derive(Clone, Debug)]
pub struct EdDsaPublicKey {
    curve: EdDsaCurve,
    value: Vec<u8>,
}

impl EdDsaPublicKey {
    /// Validate the raw public-key length. Point validation belongs to the client.
    pub fn from_bytes(curve: EdDsaCurve, value: Vec<u8>) -> Result<Self, Error> {
        if value.len() != curve.public_key_length() {
            return Err(Error::InvalidKeyOutput);
        }
        Ok(Self { curve, value })
    }

    /// Public-key curve.
    pub fn curve(&self) -> EdDsaCurve {
        self.curve
    }

    /// Raw RFC 8032 public-key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
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

fn wrapped_ec_point(value: &[u8]) -> Result<Vec<u8>, Error> {
    let length: u8 = value
        .len()
        .try_into()
        .map_err(|_| Error::InvalidParameters("EdDSA public key length"))?;
    let mut wrapped = Vec::with_capacity(value.len() + 2);
    wrapped.extend_from_slice(&[0x04, length]);
    wrapped.extend_from_slice(value);
    Ok(wrapped)
}

fn curve_of(object: &Object<'_, '_>, class: ObjectClass) -> Result<EdDsaCurve, Error> {
    if !matches!(
        attribute(object, AttributeType::Class, true)?,
        Some(Attribute::Class(value)) if value == class
    ) || !matches!(
        attribute(object, AttributeType::KeyType, true)?,
        Some(Attribute::KeyType(KeyType::EC_EDWARDS))
    ) {
        return Err(Error::UnsupportedSigning("EdDSA key class or type"));
    }
    match attribute(object, AttributeType::EcParams, true)? {
        Some(Attribute::EcParams(value)) => EdDsaCurve::from_ec_params(&value),
        _ => Err(Error::MissingMetadata("EdDSA curve parameters")),
    }
}

fn permission(object: &Object<'_, '_>, kind: AttributeType) -> Result<bool, Error> {
    match (kind, attribute(object, kind, true)?) {
        (AttributeType::Sign, Some(Attribute::Sign(value)))
        | (AttributeType::Verify, Some(Attribute::Verify(value)))
        | (AttributeType::AlwaysAuthenticate, Some(Attribute::AlwaysAuthenticate(value))) => {
            Ok(value)
        }
        _ => Err(Error::MissingMetadata("EdDSA key permission")),
    }
}

fn allowed(object: &Object<'_, '_>) -> Result<bool, Error> {
    match attribute(object, AttributeType::AllowedMechanisms, false)? {
        None => Ok(true),
        Some(Attribute::AllowedMechanisms(value)) => {
            Ok(value.is_empty() || value.contains(&MechanismType::EDDSA))
        }
        _ => Err(Error::MissingMetadata("CKA_ALLOWED_MECHANISMS")),
    }
}

fn mechanism_support(token: &Token<'_>, curve: EdDsaCurve, verify: bool) -> Result<bool, Error> {
    if !token.mechanisms()?.contains(&MechanismType::EDDSA) {
        return Ok(false);
    }
    let info = token.mechanism_info(MechanismType::EDDSA)?;
    Ok(
        (info.min_key_size()..=info.max_key_size()).contains(&curve.bits())
            && if verify { info.verify() } else { info.sign() },
    )
}

fn capabilities(object: &Object<'_, '_>) -> Result<EdDsaCapabilities, Error> {
    let curve = curve_of(object, ObjectClass::PRIVATE_KEY)?;
    let always_authenticate = permission(object, AttributeType::AlwaysAuthenticate)?;
    // Context authentication needs a single-part sign after C_SignInit. Published
    // cryptoki exposes only multipart completion, which not every provider
    // implements for EdDSA. Do not advertise a path that cannot be completed.
    Ok(EdDsaCapabilities {
        curve,
        can_sign: !always_authenticate
            && permission(object, AttributeType::Sign)?
            && allowed(object)?
            && mechanism_support(object.session.token(), curve, false)?,
        can_verify: false,
        always_authenticate,
    })
}

fn verification_key(object: &Object<'_, '_>) -> Result<(EdDsaCurve, bool), Error> {
    let curve = curve_of(object, ObjectClass::PUBLIC_KEY)?;
    let permitted = permission(object, AttributeType::Verify)?
        && allowed(object)?
        && mechanism_support(object.session.token(), curve, true)?;
    Ok((curve, permitted))
}

impl Token<'_> {
    /// Advertised EdDSA curves with a native key-pair generation entry point.
    pub fn eddsa_generation_options(&self) -> Result<Vec<EdDsaCurve>, Error> {
        if !self
            .mechanisms()?
            .contains(&MechanismType::ECC_EDWARDS_KEY_PAIR_GEN)
        {
            return Ok(Vec::new());
        }
        let info = self.mechanism_info(MechanismType::ECC_EDWARDS_KEY_PAIR_GEN)?;
        Ok(EdDsaCurve::ALL
            .into_iter()
            .filter(|curve| {
                info.generate_key_pair()
                    && (info.min_key_size()..=info.max_key_size()).contains(&curve.bits())
            })
            .collect())
    }
}

impl<'m> Session<'m> {
    /// Generate a persistent EdDSA pair in an RW session.
    pub fn generate_eddsa_key_pair(
        &mut self,
        curve: EdDsaCurve,
        id: &[u8],
        label: &[u8],
        always_authenticate: bool,
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        validate_secret_identity(id, label)?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        if always_authenticate {
            return Err(Error::UnsupportedSigning(
                "EdDSA context authentication requires upstream single-part initialized signing",
            ));
        }
        if !self.token().eddsa_generation_options()?.contains(&curve) {
            return Err(Error::UnsupportedSigning("EdDSA key generation"));
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
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::EcParams(curve.ec_params().to_vec()),
            Attribute::Verify(true),
            Attribute::Encrypt(false),
            Attribute::Wrap(false),
            Attribute::Derive(false),
            Attribute::AllowedMechanisms(vec![MechanismType::EDDSA]),
        ];
        let private = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.to_vec()),
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::Sign(true),
            Attribute::Decrypt(false),
            Attribute::Unwrap(false),
            Attribute::Derive(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::AlwaysAuthenticate(always_authenticate),
            Attribute::AllowedMechanisms(vec![MechanismType::EDDSA]),
        ];
        let (public, private) = self.write_operation("generate EdDSA key pair", |raw| {
            raw.generate_key_pair(&Mechanism::EccEdwardsKeyPairGen, &public, &private)
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

    /// Inspect a private key's EdDSA curve and signing permissions.
    pub fn eddsa_capabilities(&mut self, key: &PrivateKeyRef) -> Result<EdDsaCapabilities, Error> {
        capabilities(&self.resolve(key.as_object_ref())?)
    }

    /// Read the public key's EdDSA curve without reading key bytes.
    pub fn eddsa_public_curve(&mut self, key: &PublicKeyRef) -> Result<EdDsaCurve, Error> {
        curve_of(&self.resolve(key.as_object_ref())?, ObjectClass::PUBLIC_KEY)
    }

    /// Read an explicitly public EdDSA key as raw RFC 8032 bytes.
    pub fn eddsa_public_key(&mut self, key: &PublicKeyRef) -> Result<EdDsaPublicKey, Error> {
        let object = self.resolve(key.as_object_ref())?;
        let curve = curve_of(&object, ObjectClass::PUBLIC_KEY)?;
        if !matches!(
            attribute(&object, AttributeType::Private, true)?,
            Some(Attribute::Private(false))
        ) {
            return Err(Error::UnsupportedSigning("private EdDSA public object"));
        }
        match attribute(&object, AttributeType::EcPoint, true)? {
            Some(Attribute::EcPoint(value)) => {
                match raw_ec_point(&value, curve.public_key_length()) {
                    Some(raw) => EdDsaPublicKey::from_bytes(curve, raw.to_vec()),
                    None => Err(Error::InvalidKeyOutput),
                }
            }
            _ => Err(Error::InvalidKeyOutput),
        }
    }

    /// Import a public EdDSA key for verification only.
    pub fn import_eddsa_public_key(
        &mut self,
        key: &EdDsaPublicKey,
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
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.to_vec()),
            Attribute::Verify(true),
            Attribute::Derive(false),
            Attribute::EcParams(key.curve().ec_params().to_vec()),
            Attribute::EcPoint(wrapped_ec_point(key.as_bytes())?),
            Attribute::AllowedMechanisms(vec![MechanismType::EDDSA]),
        ])?;
        Ok(())
    }

    /// Sign one original message with pure EdDSA.
    pub fn sign_eddsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &EdDsaRequest<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        let result = self.sign_eddsa_once(key, request, context_pin);
        let result = result.map_err(|error| {
            let unsupported = matches!(
                &error,
                Error::Backend { source, .. } if function_not_supported(source)
            );
            if unsupported {
                self.healthy.set(true);
            }
            map_function_not_supported(
                error,
                Error::UnsupportedSigning("EdDSA signing unavailable"),
            )
        });
        if matches!(
            &result,
            Err(Error::Backend { .. } | Error::TokenChanged | Error::InvalidSignature)
        ) {
            self.healthy.set(false);
        }
        result
    }

    fn sign_eddsa_once(
        &mut self,
        key: &PrivateKeyRef,
        request: &EdDsaRequest<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        let object = self.resolve(key.as_object_ref())?;
        let capabilities = capabilities(&object)?;
        if capabilities.curve != request.curve || !capabilities.can_sign {
            return Err(Error::UnsupportedSigning(
                "EdDSA curve, permissions or context-authentication profile",
            ));
        }
        if context_pin.is_some() {
            return Err(Error::InvalidParameters(
                "context PIN for an EdDSA key without a supported context profile",
            ));
        }
        let mechanism = request.curve.mechanism();
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        let signature = raw
            .sign(&mechanism, object.handle, request.message)
            .map_err(|e| backend("EdDSA sign", e))?;
        if signature.len() != request.curve.signature_length() {
            return Err(Error::InvalidSignature);
        }
        object.session.healthy.set(true);
        Ok(signature)
    }

    /// Verify one pure EdDSA signature on the token.
    pub fn verify_eddsa(
        &mut self,
        key: &PublicKeyRef,
        request: &EdDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        let result = self.verify_eddsa_once(key, request, signature);
        let result = result.map_err(|error| {
            let unsupported = matches!(
                &error,
                Error::Backend { source, .. } if function_not_supported(source)
            );
            if unsupported {
                self.healthy.set(true);
            }
            map_function_not_supported(
                error,
                Error::UnsupportedVerification("EdDSA verification unavailable"),
            )
        });
        if matches!(&result, Err(Error::Backend { .. } | Error::TokenChanged)) {
            self.healthy.set(false);
        }
        result
    }

    fn verify_eddsa_once(
        &mut self,
        key: &PublicKeyRef,
        request: &EdDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        if signature.len() != request.curve.signature_length() {
            return Err(Error::SignatureMismatch);
        }
        let object = self.resolve(key.as_object_ref())?;
        let (curve, permitted) = verification_key(&object)?;
        if curve != request.curve || !permitted {
            return Err(Error::UnsupportedSigning(
                "EdDSA verification permissions or curve",
            ));
        }
        let mechanism = request.curve.mechanism();
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        match raw.verify(&mechanism, object.handle, request.message, signature) {
            Ok(()) => {
                object.session.healthy.set(true);
                Ok(())
            }
            Err(CryptokiError::Pkcs11(
                RvError::SignatureInvalid | RvError::SignatureLenRange,
                Function::Verify,
            )) => {
                object.session.healthy.set(true);
                Err(Error::SignatureMismatch)
            }
            Err(error) => Err(backend("EdDSA verify", error)),
        }
    }
}

use crate::Function;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curves_and_parameter_encodings_are_explicit() {
        for (curve, bits, public, signature, params) in [
            (
                EdDsaCurve::Ed25519,
                255,
                32,
                64,
                &[6u8, 3, 43, 101, 112][..],
            ),
            (EdDsaCurve::Ed448, 448, 57, 114, &[6u8, 3, 43, 101, 113][..]),
        ] {
            assert_eq!(curve.bits(), bits);
            assert_eq!(curve.public_key_length(), public);
            assert_eq!(curve.signature_length(), signature);
            assert_eq!(curve.ec_params(), params);
            assert_eq!(EdDsaCurve::from_ec_params(params).unwrap(), curve);
        }
        assert!(EdDsaCurve::from_ec_params(&[6, 3, 43, 101, 110]).is_err());
        assert_eq!(raw_ec_point(&[4, 1, 7], 1), Some(&[7u8][..]));
        assert_eq!(raw_ec_point(&[7], 1), Some(&[7u8][..]));
        assert_eq!(wrapped_ec_point(&[7; 32]).unwrap(), {
            let mut value = vec![4, 32];
            value.extend_from_slice(&[7; 32]);
            value
        });
    }
}
