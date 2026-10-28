// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeInfo, AttributeType, Error, KeyType, MechanismInfo, MechanismType, Object,
    ObjectClass, ObjectRef, Pin, PrivateKeyRef, PublicKeyRef, Session, SessionMode, Token,
    error::backend, key_operations::validate_secret_identity,
};
use cryptoki::{
    context::Function,
    error::{Error as CryptokiError, RvError},
    mechanism::{
        Mechanism,
        eddsa::{EddsaParams, EddsaSignatureScheme},
    },
    session::UserType,
};

/// RFC 8032 Edwards signing curves. These are separate from ECDSA and ECDH curves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdDsaCurve {
    /// Ed25519 with no prehash or context.
    Ed25519,
    /// Ed448 with no prehash and an empty context.
    Ed448,
}
impl EdDsaCurve {
    /// Field size used by PKCS #11 mechanism bounds, in bits.
    pub fn bits(self) -> usize {
        match self {
            Self::Ed25519 => 255,
            Self::Ed448 => 448,
        }
    }
    /// Raw RFC 8032 public-key length, in bytes.
    pub fn public_key_length(self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::Ed448 => 57,
        }
    }
    /// Raw RFC 8032 signature length, in bytes.
    pub fn signature_length(self) -> usize {
        self.public_key_length() * 2
    }
    /// DER named-curve OID used for CKA_EC_PARAMS.
    pub fn ec_params(self) -> &'static [u8] {
        match self {
            Self::Ed25519 => &[6, 3, 43, 101, 112],
            Self::Ed448 => &[6, 3, 43, 101, 113],
        }
    }
    /// Decode the standard named-curve OID or PrintableString curve name.
    /// Explicit parameters, Montgomery curves and malformed DER are rejected.
    pub fn from_ec_params(params: &[u8]) -> Result<Self, Error> {
        match params {
            [6, 3, 43, 101, 112] | b"\x13\x0cedwards25519" => Ok(Self::Ed25519),
            [6, 3, 43, 101, 113] | b"\x13\x0aedwards448" => Ok(Self::Ed448),
            _ => Err(Error::UnsupportedSigning("EdDSA curve parameters")),
        }
    }
    fn named_curve_mechanism(self) -> Mechanism<'static> {
        Mechanism::Eddsa(EddsaParams::new(match self {
            Self::Ed25519 => EddsaSignatureScheme::Ed25519,
            Self::Ed448 => EddsaSignatureScheme::Ed448(&[]),
        }))
    }
}

/// Pure EdDSA request. Pass the original message, including an empty message;
/// external digests, contexts and prehash variants are not represented by this API.
#[derive(Clone, Copy)]
pub struct EdDsaRequest<'a> {
    /// Expected curve, checked again against the selected key before execution.
    pub curve: EdDsaCurve,
    /// Original message. Debug omits its contents.
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
    /// Curve read from CKA_EC_PARAMS.
    pub curve: EdDsaCurve,
    /// Private-key permission, allowed mechanisms and native support permit signing.
    pub can_sign: bool,
    /// Public-key permission, allowed mechanisms and native support permit verification.
    pub can_verify: bool,
    /// Private keys may require a context-specific PIN after signing initialization.
    pub always_authenticate: bool,
}

/// Length-checked public RFC 8032 bytes. Point validation belongs to the client verifier.
#[derive(Clone, Debug)]
pub struct EdDsaPublicKey {
    curve: EdDsaCurve,
    value: Vec<u8>,
}
impl EdDsaPublicKey {
    /// Check the exact encoding length. Does not validate the curve point or ownership.
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
    /// Raw public-key bytes, without an ASN.1 wrapper.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}

const ATTRIBUTE_LIMIT: usize = 4096;
fn attribute(
    object: &Object<'_, '_>,
    kind: AttributeType,
    required: bool,
) -> Result<Option<Attribute>, Error> {
    match object.attribute_info(&[kind])?.first() {
        Some(AttributeInfo::Available(_)) => {
            let values = object.read_attributes_bounded(&[kind], ATTRIBUTE_LIMIT)?;
            values
                .expose_values()
                .first()
                .cloned()
                .map(Some)
                .ok_or(Error::MissingMetadata(
                    "EdDSA attribute changed during read",
                ))
        }
        Some(AttributeInfo::TypeInvalid) if !required => Ok(None),
        _ => Err(Error::MissingMetadata("EdDSA key attribute")),
    }
}
fn key_parameters(
    object: &Object<'_, '_>,
    class: ObjectClass,
) -> Result<(EdDsaCurve, Mechanism<'static>), Error> {
    if !matches!(attribute(object, AttributeType::Class, true)?, Some(Attribute::Class(value)) if value == class)
        || !matches!(
            attribute(object, AttributeType::KeyType, true)?,
            Some(Attribute::KeyType(KeyType::EC_EDWARDS))
        )
    {
        return Err(Error::UnsupportedSigning("EdDSA key class or type"));
    }
    match attribute(object, AttributeType::EcParams, true)? {
        Some(Attribute::EcParams(value)) => {
            let curve = EdDsaCurve::from_ec_params(&value)?;
            // OID keys identify the RFC 8410 pure algorithm implicitly. Only
            // RFC 8032 curve-name keys use parameters to select a variant.
            let mechanism = if value[0] == 0x13 {
                curve.named_curve_mechanism()
            } else {
                Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure))
            };
            Ok((curve, mechanism))
        }
        _ => Err(Error::MissingMetadata("EdDSA curve parameters")),
    }
}
fn permission(object: &Object<'_, '_>, kind: AttributeType) -> Result<bool, Error> {
    match attribute(object, kind, true)? {
        Some(
            Attribute::Sign(value)
            | Attribute::Verify(value)
            | Attribute::AlwaysAuthenticate(value),
        ) => Ok(value),
        _ => Err(Error::MissingMetadata("EdDSA key permission")),
    }
}
fn supported(
    token: &Token<'_>,
    curve: EdDsaCurve,
    mechanism: MechanismType,
    flag: impl FnOnce(MechanismInfo) -> bool,
) -> Result<bool, Error> {
    if !token.mechanisms()?.contains(&mechanism) {
        return Ok(false);
    }
    let info = token.mechanism_info(mechanism)?;
    Ok((info.min_key_size()..=info.max_key_size()).contains(&curve.bits()) && flag(info))
}
fn capabilities(object: &Object<'_, '_>) -> Result<(EdDsaCapabilities, Mechanism<'static>), Error> {
    let class = match attribute(object, AttributeType::Class, true)? {
        Some(Attribute::Class(value))
            if value == ObjectClass::PRIVATE_KEY || value == ObjectClass::PUBLIC_KEY =>
        {
            value
        }
        _ => return Err(Error::UnsupportedSigning("EdDSA key class")),
    };
    let (curve, mechanism) = key_parameters(object, class)?;
    let allowed = match attribute(object, AttributeType::AllowedMechanisms, false)? {
        None => true,
        Some(Attribute::AllowedMechanisms(value)) => {
            value.is_empty() || value.contains(&MechanismType::EDDSA)
        }
        _ => return Err(Error::MissingMetadata("CKA_ALLOWED_MECHANISMS")),
    };
    let raw = object.session.token().module.raw()?;
    let always_authenticate =
        class == ObjectClass::PRIVATE_KEY && permission(object, AttributeType::AlwaysAuthenticate)?;
    Ok((
        EdDsaCapabilities {
            curve,
            can_sign: class == ObjectClass::PRIVATE_KEY
                && permission(object, AttributeType::Sign)?
                && allowed
                && raw.is_fn_supported(Function::SignInit)
                && raw.is_fn_supported(Function::Sign)
                && (!always_authenticate || raw.is_fn_supported(Function::Login))
                && supported(
                    object.session.token(),
                    curve,
                    MechanismType::EDDSA,
                    |info| info.sign(),
                )?,
            can_verify: class == ObjectClass::PUBLIC_KEY
                && permission(object, AttributeType::Verify)?
                && allowed
                && raw.is_fn_supported(Function::VerifyInit)
                && raw.is_fn_supported(Function::Verify)
                && supported(
                    object.session.token(),
                    curve,
                    MechanismType::EDDSA,
                    |info| info.verify(),
                )?,
            always_authenticate,
        },
        mechanism,
    ))
}
impl Token<'_> {
    /// Advertised Edwards generation choices. Providers may still reject templates.
    pub fn eddsa_generation_options(&self) -> Result<Vec<EdDsaCurve>, Error> {
        if !self
            .module
            .raw()?
            .is_fn_supported(Function::GenerateKeyPair)
        {
            return Ok(Vec::new());
        }
        let mut choices = Vec::new();
        for curve in [EdDsaCurve::Ed25519, EdDsaCurve::Ed448] {
            if supported(
                self,
                curve,
                MechanismType::ECC_EDWARDS_KEY_PAIR_GEN,
                |info| info.generate_key_pair(),
            )? {
                choices.push(curve);
            }
        }
        Ok(choices)
    }
}
impl<'m> Session<'m> {
    /// Generate one persistent signing pair with bounded explicit ID/label.
    /// Private material is sensitive and nonextractable. Requires RW mode and
    /// rejects existing pair IDs; concurrent writers can race. No retry or rollback.
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
            Attribute::Verify(true),
            Attribute::EcParams(curve.ec_params().to_vec()),
            Attribute::Derive(false),
            Attribute::AllowedMechanisms(vec![MechanismType::EDDSA]),
        ];
        let private = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.to_vec()),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::AlwaysAuthenticate(always_authenticate),
            Attribute::Derive(false),
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
    /// Read the uniquely selected Edwards public/private key's current capabilities.
    pub fn eddsa_capabilities(&mut self, key: &ObjectRef) -> Result<EdDsaCapabilities, Error> {
        capabilities(&self.resolve_bounded(key, ATTRIBUTE_LIMIT)?).map(|(caps, _)| caps)
    }
    /// Read bounded public metadata, requiring a public, non-private object and
    /// a canonical DER OCTET STRING of the curve's exact public-key length.
    pub fn eddsa_public_key(&mut self, key: &PublicKeyRef) -> Result<EdDsaPublicKey, Error> {
        let object = self.resolve_bounded(key.as_object_ref(), ATTRIBUTE_LIMIT)?;
        let (curve, _) = key_parameters(&object, ObjectClass::PUBLIC_KEY)?;
        if !matches!(
            attribute(&object, AttributeType::Private, true)?,
            Some(Attribute::Private(false))
        ) {
            return Err(Error::UnsupportedSigning("private EdDSA public object"));
        }
        match attribute(&object, AttributeType::EcPoint, true)? {
            Some(Attribute::EcPoint(value))
                if value.len() == curve.public_key_length() + 2
                    && value[..2] == [4, curve.public_key_length() as u8] =>
            {
                EdDsaPublicKey::from_bytes(curve, value[2..].to_vec())
            }
            _ => Err(Error::InvalidKeyOutput),
        }
    }
    /// Sign once with the native pure profile into exactly bounded output.
    /// Rechecks curve/permissions and logs in after initialization for keys with
    /// always-authenticate. Errors after initialization invalidate the session.
    pub fn sign_eddsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &EdDsaRequest<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        let object = self.resolve_bounded(key.as_object_ref(), ATTRIBUTE_LIMIT)?;
        let (caps, mechanism) = capabilities(&object)?;
        if !caps.can_sign || caps.curve != request.curve {
            return Err(Error::UnsupportedSigning("EdDSA curve or permissions"));
        }
        let pin = if caps.always_authenticate {
            object
                .session
                .login_pin(context_pin.ok_or(Error::ContextAuthenticationRequired)?)?
        } else {
            if context_pin.is_some() {
                return Err(Error::InvalidParameters(
                    "context PIN for a key without always-authenticate",
                ));
            }
            None
        };
        let raw = object.session.raw()?;
        let mut signature = vec![0; request.curve.signature_length()];
        object.session.healthy.set(false);
        raw.sign_init(&mechanism, object.handle)
            .map_err(|e| backend("EdDSA sign init", e))?;
        if caps.always_authenticate {
            raw.login(UserType::ContextSpecific, pin)
                .map_err(|e| backend("EdDSA context login", e))?;
        }
        let written = raw
            .sign_initialized_into(request.message, &mut signature)
            .map_err(|e| backend("EdDSA sign", e))?;
        if written != signature.len() {
            return Err(Error::InvalidSignature);
        }
        object.session.healthy.set(true);
        Ok(signature)
    }
    /// Verify the original message on the token. A malformed signature or native
    /// signature mismatch is reusable; other errors after initialization are not.
    pub fn verify_eddsa(
        &mut self,
        key: &PublicKeyRef,
        request: &EdDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        if signature.len() != request.curve.signature_length() {
            return Err(Error::SignatureMismatch);
        }
        let object = self.resolve_bounded(key.as_object_ref(), ATTRIBUTE_LIMIT)?;
        let (caps, mechanism) = capabilities(&object)?;
        if !caps.can_verify || caps.curve != request.curve {
            return Err(Error::UnsupportedVerification("EdDSA curve or permissions"));
        }
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
