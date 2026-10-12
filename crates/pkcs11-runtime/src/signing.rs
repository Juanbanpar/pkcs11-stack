// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeInfo, AttributeType, Error, MechanismType, Object, ObjectRef, Pin, Session,
    error::backend,
};
use cryptoki::{
    mechanism::{
        Mechanism,
        rsa::{PkcsMgfType, PkcsPssParams},
    },
    object::KeyType,
    session::UserType,
};
use pkcs11_locator::Pkcs11Uri;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::borrow::Cow;

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

/// Supported SHA-2 digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}
impl DigestAlgorithm {
    /// Digest length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
    fn mechanism(self) -> MechanismType {
        match self {
            Self::Sha256 => MechanismType::SHA256,
            Self::Sha384 => MechanismType::SHA384,
            Self::Sha512 => MechanismType::SHA512,
        }
    }
    fn mgf(self) -> PkcsMgfType {
        match self {
            Self::Sha256 => PkcsMgfType::MGF1_SHA256,
            Self::Sha384 => PkcsMgfType::MGF1_SHA384,
            Self::Sha512 => PkcsMgfType::MGF1_SHA512,
        }
    }
    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}
/// Generic signature family, independent of protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5, with a SHA-2 DigestInfo.
    RsaPkcs1,
    /// RSASSA-PSS, requiring explicit MGF1 digest and salt length.
    RsaPss,
    /// ECDSA, returned as fixed-width PKCS#11 r || s.
    Ecdsa,
}
/// Explicit PSS parameters. No default salt or MGF is inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PssParameters {
    /// Digest used by MGF1; independent of the message digest.
    pub mgf_digest: DigestAlgorithm,
    /// Exact salt size in bytes.
    pub salt_len: usize,
}
/// Debug omits input bytes.
#[derive(Clone, Copy)]
pub enum SignInput<'a> {
    /// Unhashed message.
    Message(&'a [u8]),
    /// Precomputed digest of exactly the selected digest length.
    Digest(&'a [u8]),
}
impl std::fmt::Debug for SignInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Message(_) => "Message([REDACTED])",
            Self::Digest(_) => "Digest([REDACTED])",
        })
    }
}
/// A signing request, with no protocol-specific encodings.
#[derive(Debug, Clone, Copy)]
pub struct SignRequest<'a> {
    /// Signature family.
    pub algorithm: SignatureAlgorithm,
    /// Message digest algorithm, also identifying a supplied digest.
    pub digest: DigestAlgorithm,
    /// Message or digest; these are never interchangeable.
    pub input: SignInput<'a>,
    /// Required for PSS and forbidden for other algorithms.
    pub pss: Option<PssParameters>,
}
/// Policy for unhashed messages. Precomputed digests are always caller-hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashingPolicy {
    /// Require a combined token mechanism for messages.
    TokenOnly,
    /// Prefer combined mechanisms, allowing software hashing if unavailable.
    AllowSoftware,
    /// Explicitly hash messages in software and use a raw signing mechanism.
    SoftwareOnly,
}
/// Application restrictions, intersected with actual key/token capabilities.
#[derive(Debug, Clone)]
pub struct SigningPolicy {
    /// Message hashing boundary.
    pub hashing: HashingPolicy,
    /// Minimum RSA modulus size in bits.
    pub minimum_rsa_bits: usize,
    /// Allowed signature families.
    pub algorithms: Vec<SignatureAlgorithm>,
    /// Allowed named EC curves.
    pub curves: Vec<NamedCurve>,
    /// Allowed message and MGF1 digests.
    pub digests: Vec<DigestAlgorithm>,
}
impl Default for SigningPolicy {
    fn default() -> Self {
        Self {
            hashing: HashingPolicy::TokenOnly,
            minimum_rsa_bits: 2048,
            curves: vec![NamedCurve::P256, NamedCurve::P384, NamedCurve::P521],
            algorithms: vec![
                SignatureAlgorithm::RsaPkcs1,
                SignatureAlgorithm::RsaPss,
                SignatureAlgorithm::Ecdsa,
            ],
            digests: vec![
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
            ],
        }
    }
}
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
}
impl KeyKind {
    fn bits(self) -> usize {
        match self {
            Self::Rsa { bits } => bits,
            Self::Ec(curve) => curve.bits(),
        }
    }
}
/// Mechanism advertisement, including signing flags and key-size bounds in bits.
#[derive(Debug, Clone)]
pub struct SigningMechanism {
    /// PKCS#11 mechanism identifier.
    pub mechanism: MechanismType,
    /// CKF_SIGN is present.
    pub can_sign: bool,
    /// Minimum supported RSA/EC key size in bits.
    pub minimum_bits: usize,
    /// Maximum supported RSA/EC key size in bits.
    pub maximum_bits: usize,
}
/// An inspectable capability snapshot. Signing always rediscovers it in the live session.
#[derive(Debug, Clone)]
pub struct KeyCapabilities {
    /// Key type and public size/curve.
    pub key: KeyKind,
    /// CKA_SIGN.
    pub can_sign: bool,
    /// CKA_ALWAYS_AUTHENTICATE.
    pub always_authenticate: bool,
    /// None means the attribute is unsupported; an empty list means unrestricted.
    pub allowed_mechanisms: Option<Vec<MechanismType>>,
    /// Actual token mechanism information.
    pub mechanisms: Vec<SigningMechanism>,
}
/// Where the input message is hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashLocation {
    /// Token combined hash/sign mechanism.
    Token,
    /// Runtime software hashing explicitly permitted by policy.
    Software,
    /// Digest supplied by caller.
    Caller,
}
/// A planning result, never an authorization or a cached operational handle.
#[derive(Debug, Clone)]
pub struct SignPlan {
    mechanism: MechanismType,
    hashing: HashLocation,
    multipart: bool,
}
impl SignPlan {
    /// Selected PKCS#11 mechanism.
    pub fn mechanism(&self) -> MechanismType {
        self.mechanism
    }
    /// Selected hashing boundary.
    pub fn hash_location(&self) -> HashLocation {
        self.hashing
    }
    /// Whether context login must occur between init and multipart signing.
    pub fn context_authentication(&self) -> bool {
        self.multipart
    }
}
impl KeyCapabilities {
    /// Pure planning, usable without loading a module. Unknown facts fail closed.
    pub fn plan(
        &self,
        request: &SignRequest<'_>,
        policy: &SigningPolicy,
    ) -> Result<SignPlan, Error> {
        if self.key.bits() == 0 {
            return Err(Error::InvalidParameters("zero key size"));
        }
        if !self.can_sign
            || !policy.algorithms.contains(&request.algorithm)
            || !policy.digests.contains(&request.digest)
        {
            return Err(Error::UnsupportedSigning("key or policy disallows signing"));
        }
        match (request.algorithm, self.key) {
            (SignatureAlgorithm::Ecdsa, KeyKind::Ec(curve)) if policy.curves.contains(&curve) => {}
            (SignatureAlgorithm::RsaPkcs1 | SignatureAlgorithm::RsaPss, KeyKind::Rsa { bits })
                if bits >= policy.minimum_rsa_bits => {}
            _ => return Err(Error::UnsupportedSigning("key type or size")),
        }
        if let SignInput::Digest(value) = request.input {
            if value.len() != request.digest.output_len() {
                return Err(Error::InvalidParameters("digest length"));
            }
        }
        match (request.algorithm, request.pss) {
            (SignatureAlgorithm::RsaPss, Some(pss)) => {
                if !policy.digests.contains(&pss.mgf_digest) {
                    return Err(Error::UnsupportedSigning("MGF digest policy"));
                }
                let encoded_len = (self.key.bits() - 1).div_ceil(8);
                if pss.salt_len > encoded_len.saturating_sub(request.digest.output_len() + 2)
                    || encoded_len < request.digest.output_len() + 2
                {
                    return Err(Error::InvalidParameters("PSS salt does not fit modulus"));
                }
            }
            (SignatureAlgorithm::RsaPss, None) => {
                return Err(Error::InvalidParameters("PSS parameters required"));
            }
            (_, Some(_)) => {
                return Err(Error::InvalidParameters(
                    "PSS parameters on another algorithm",
                ));
            }
            _ => {}
        }
        if request.algorithm == SignatureAlgorithm::RsaPkcs1
            && self.key.bits().div_ceil(8) < request.digest.output_len() + 19 + 11
        {
            return Err(Error::InvalidParameters("DigestInfo does not fit modulus"));
        }
        let combined = mechanism(request, true)?.mechanism_type();
        let raw = mechanism(request, false)?.mechanism_type();
        let supports = |m| {
            self.mechanisms.iter().any(|v| {
                v.mechanism == m
                    && v.can_sign
                    && self.key.bits() >= v.minimum_bits
                    && self.key.bits() <= v.maximum_bits
            }) && self
                .allowed_mechanisms
                .as_ref()
                .is_none_or(|allowed| allowed.is_empty() || allowed.contains(&m))
        };
        let (selected, hashing) = match request.input {
            SignInput::Digest(_) if supports(raw) => (raw, HashLocation::Caller),
            SignInput::Message(_)
                if policy.hashing != HashingPolicy::SoftwareOnly && supports(combined) =>
            {
                (combined, HashLocation::Token)
            }
            SignInput::Message(_)
                if policy.hashing != HashingPolicy::TokenOnly && supports(raw) =>
            {
                (raw, HashLocation::Software)
            }
            _ => return Err(Error::UnsupportedSigning("no permitted mechanism")),
        };
        if self.always_authenticate && hashing != HashLocation::Token {
            return Err(Error::UnsupportedSigning(
                "context authentication needs a combined hash/sign mechanism with cryptoki 0.12",
            ));
        }
        Ok(SignPlan {
            mechanism: selected,
            hashing,
            multipart: self.always_authenticate,
        })
    }
}
fn mechanism(request: &SignRequest<'_>, combined: bool) -> Result<Mechanism<'static>, Error> {
    use DigestAlgorithm::*;
    Ok(match request.algorithm {
        SignatureAlgorithm::RsaPkcs1 => {
            if combined {
                match request.digest {
                    Sha256 => Mechanism::Sha256RsaPkcs,
                    Sha384 => Mechanism::Sha384RsaPkcs,
                    Sha512 => Mechanism::Sha512RsaPkcs,
                }
            } else {
                Mechanism::RsaPkcs
            }
        }
        SignatureAlgorithm::Ecdsa => {
            if combined {
                match request.digest {
                    Sha256 => Mechanism::EcdsaSha256,
                    Sha384 => Mechanism::EcdsaSha384,
                    Sha512 => Mechanism::EcdsaSha512,
                }
            } else {
                Mechanism::Ecdsa
            }
        }
        SignatureAlgorithm::RsaPss => {
            let pss = request
                .pss
                .ok_or(Error::InvalidParameters("PSS parameters required"))?;
            let params = PkcsPssParams {
                hash_alg: request.digest.mechanism(),
                mgf: pss.mgf_digest.mgf(),
                s_len: pss
                    .salt_len
                    .try_into()
                    .map_err(|_| Error::InvalidParameters("PSS salt overflow"))?,
            };
            if combined {
                match request.digest {
                    Sha256 => Mechanism::Sha256RsaPkcsPss(params),
                    Sha384 => Mechanism::Sha384RsaPkcsPss(params),
                    Sha512 => Mechanism::Sha512RsaPkcsPss(params),
                }
            } else {
                Mechanism::RsaPkcsPss(params)
            }
        }
    })
}
fn digest_info(digest: DigestAlgorithm, data: &[u8]) -> Vec<u8> {
    // DER DigestInfo for the three fixed SHA-2 OIDs, with explicit NULL parameters.
    let (len, oid) = match digest {
        DigestAlgorithm::Sha256 => (0x31, 1),
        DigestAlgorithm::Sha384 => (0x41, 2),
        DigestAlgorithm::Sha512 => (0x51, 3),
    };
    let mut encoded = vec![
        0x30,
        len,
        0x30,
        0x0d,
        0x06,
        0x09,
        0x60,
        0x86,
        0x48,
        0x01,
        0x65,
        0x03,
        0x04,
        0x02,
        oid,
        0x05,
        0x00,
        0x04,
        digest.output_len() as u8,
    ];
    encoded.extend_from_slice(data);
    encoded
}

pub(crate) fn attribute(
    object: &Object<'_, '_>,
    ty: AttributeType,
    required: bool,
) -> Result<Option<Attribute>, Error> {
    let info = object.attribute_info(&[ty])?;
    match info.first() {
        Some(AttributeInfo::Available(_)) => {
            let values = object.read_attributes(&[ty])?;
            let value = values.expose_values().first().cloned();
            if value.is_none() {
                return Err(Error::MissingMetadata("attribute changed during read"));
            }
            Ok(value)
        }
        Some(AttributeInfo::TypeInvalid) if !required => Ok(None),
        _ => Err(Error::MissingMetadata("required or restricted attribute")),
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
        _ => Err(Error::UnsupportedSigning("key type")),
    }
}
fn capabilities(object: &Object<'_, '_>) -> Result<KeyCapabilities, Error> {
    let key = key_kind(object)?;
    let can_sign = match attribute(object, AttributeType::Sign, true)? {
        Some(Attribute::Sign(value)) => value,
        _ => return Err(Error::MissingMetadata("CKA_SIGN")),
    };
    let always_authenticate = match attribute(object, AttributeType::AlwaysAuthenticate, true)? {
        Some(Attribute::AlwaysAuthenticate(value)) => value,
        _ => return Err(Error::MissingMetadata("CKA_ALWAYS_AUTHENTICATE")),
    };
    let allowed_mechanisms = match attribute(object, AttributeType::AllowedMechanisms, false)? {
        Some(Attribute::AllowedMechanisms(value)) => Some(value),
        None => None,
        _ => return Err(Error::MissingMetadata("CKA_ALLOWED_MECHANISMS")),
    };
    let token = object.session.token();
    let mut mechanisms = Vec::new();
    // Only inspect families whose size units and parameter handling we implement.
    for mechanism in token.mechanisms()? {
        if !supported_mechanism(mechanism) {
            continue;
        }
        let info = token.mechanism_info(mechanism)?;
        mechanisms.push(SigningMechanism {
            mechanism,
            can_sign: info.sign(),
            minimum_bits: info.min_key_size(),
            maximum_bits: info.max_key_size(),
        });
    }
    Ok(KeyCapabilities {
        key,
        can_sign,
        always_authenticate,
        allowed_mechanisms,
        mechanisms,
    })
}
fn supported_mechanism(m: MechanismType) -> bool {
    [
        MechanismType::RSA_PKCS,
        MechanismType::RSA_PKCS_PSS,
        MechanismType::ECDSA,
        MechanismType::SHA256_RSA_PKCS,
        MechanismType::SHA384_RSA_PKCS,
        MechanismType::SHA512_RSA_PKCS,
        MechanismType::SHA256_RSA_PKCS_PSS,
        MechanismType::SHA384_RSA_PKCS_PSS,
        MechanismType::SHA512_RSA_PKCS_PSS,
        MechanismType::ECDSA_SHA256,
        MechanismType::ECDSA_SHA384,
        MechanismType::ECDSA_SHA512,
    ]
    .contains(&m)
}
impl Session<'_> {
    /// Discover current signing capability from the resolved private key and token.
    pub fn key_capabilities(&mut self, key: &PrivateKeyRef) -> Result<KeyCapabilities, Error> {
        capabilities(&self.resolve(&key.0)?)
    }
    /// Resolve, rediscover, plan and sign once. No operation is transparently retried.
    ///
    /// Backend failures discard this session from a pool. Context-specific PINs
    /// are borrowed only for this call. Output is RSA bytes or fixed-width ECDSA r || s.
    pub fn sign(
        &mut self,
        key: &PrivateKeyRef,
        request: &SignRequest<'_>,
        policy: &SigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        let result = self.sign_once(key, request, policy, context_pin);
        if matches!(
            &result,
            Err(Error::Backend { .. } | Error::TokenChanged | Error::InvalidSignature)
        ) {
            self.healthy.set(false);
        }
        result
    }
    fn sign_once(
        &mut self,
        key: &PrivateKeyRef,
        request: &SignRequest<'_>,
        policy: &SigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        let object = self.resolve(&key.0)?;
        let capabilities = capabilities(&object)?;
        let plan = capabilities.plan(request, policy)?;
        let pin = if plan.multipart {
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
        let mut data = match request.input {
            SignInput::Message(value) if plan.hashing == HashLocation::Software => {
                Cow::Owned(request.digest.hash(value))
            }
            SignInput::Message(value) | SignInput::Digest(value) => Cow::Borrowed(value),
        };
        if plan.hashing != HashLocation::Token && request.algorithm == SignatureAlgorithm::RsaPkcs1
        {
            data = Cow::Owned(digest_info(request.digest, &data));
        }
        let mechanism = mechanism(request, plan.hashing == HashLocation::Token)?;
        let raw = object.session.raw()?;
        // A panic/error after init must never return an active operation to the pool.
        object.session.healthy.set(false);
        let signature = if plan.multipart {
            raw.sign_init(&mechanism, object.handle)
                .map_err(|e| backend("sign init", e))?;
            raw.login(UserType::ContextSpecific, pin)
                .map_err(|e| backend("context login", e))?;
            raw.sign_update(&data)
                .map_err(|e| backend("sign update", e))?;
            raw.sign_final().map_err(|e| backend("sign final", e))?
        } else {
            raw.sign(&mechanism, object.handle, &data)
                .map_err(|e| backend("sign", e))?
        };
        let expected = match capabilities.key {
            KeyKind::Rsa { bits } => bits.div_ceil(8),
            KeyKind::Ec(curve) => 2 * curve.bits().div_ceil(8),
        };
        if signature.len() != expected {
            return Err(Error::InvalidSignature);
        }
        object.session.healthy.set(true);
        Ok(signature)
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
        KeyKind::Ec(_) => {
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
        public_metadata(&session.resolve(&self.0)?)
    }
}
impl PublicKeyRef {
    /// Read public material from an independently selected public object.
    pub fn public_metadata(&self, session: &mut Session<'_>) -> Result<PublicKeyMetadata, Error> {
        public_metadata(&session.resolve(&self.0)?)
    }
}
impl CertificateRef {
    /// Read certificate bytes without interpreting trust or assuming key association.
    pub fn der(&self, session: &mut Session<'_>) -> Result<Vec<u8>, Error> {
        match attribute(&session.resolve(&self.0)?, AttributeType::Value, true)? {
            Some(Attribute::Value(v)) => Ok(v),
            _ => Err(Error::MissingMetadata("certificate value")),
        }
    }
}
