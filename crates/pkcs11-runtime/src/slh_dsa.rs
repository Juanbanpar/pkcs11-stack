// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeType, Error, MechanismType, Object, ObjectClass, Pin, PrivateKeyRef,
    PublicKeyRef, Session, SessionMode, Token,
    error::{backend, function_not_supported, map_function_not_supported},
    signing::attribute,
};
use cryptoki::{
    context::Function,
    error::{Error as CryptokiError, RvError},
    mechanism::{
        Mechanism,
        dsa::{HedgeType, SignAdditionalContext},
    },
    object::{KeyType, ParameterSetType, SlhDsaParameterSetType},
    session::UserType,
};

/// FIPS 205 SLH-DSA parameter sets. Mechanism bounds use public-key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlhDsaParameterSet {
    /// SLH-DSA-SHA2-128s.
    Sha2_128S,
    /// SLH-DSA-SHA2-128f.
    Sha2_128F,
    /// SLH-DSA-SHA2-192s.
    Sha2_192S,
    /// SLH-DSA-SHA2-192f.
    Sha2_192F,
    /// SLH-DSA-SHA2-256s.
    Sha2_256S,
    /// SLH-DSA-SHA2-256f.
    Sha2_256F,
    /// SLH-DSA-SHAKE-128s.
    Shake128S,
    /// SLH-DSA-SHAKE-128f.
    Shake128F,
    /// SLH-DSA-SHAKE-192s.
    Shake192S,
    /// SLH-DSA-SHAKE-192f.
    Shake192F,
    /// SLH-DSA-SHAKE-256s.
    Shake256S,
    /// SLH-DSA-SHAKE-256f.
    Shake256F,
}
impl SlhDsaParameterSet {
    /// All twelve standardized parameter sets. Provider support is advisory.
    pub const ALL: [Self; 12] = [
        Self::Sha2_128S,
        Self::Sha2_128F,
        Self::Sha2_192S,
        Self::Sha2_192F,
        Self::Sha2_256S,
        Self::Sha2_256F,
        Self::Shake128S,
        Self::Shake128F,
        Self::Shake192S,
        Self::Shake192F,
        Self::Shake256S,
        Self::Shake256F,
    ];
    /// Raw FIPS 205 public-key length in bytes.
    pub fn public_key_length(self) -> usize {
        match self {
            Self::Sha2_128S => 32,
            Self::Sha2_128F => 32,
            Self::Sha2_192S => 48,
            Self::Sha2_192F => 48,
            Self::Sha2_256S => 64,
            Self::Sha2_256F => 64,
            Self::Shake128S => 32,
            Self::Shake128F => 32,
            Self::Shake192S => 48,
            Self::Shake192F => 48,
            Self::Shake256S => 64,
            Self::Shake256F => 64,
        }
    }
    /// Exact FIPS 205 signature length in bytes.
    pub fn signature_length(self) -> usize {
        match self {
            Self::Sha2_128S => 7856,
            Self::Sha2_128F => 17088,
            Self::Sha2_192S => 16224,
            Self::Sha2_192F => 35664,
            Self::Sha2_256S => 29792,
            Self::Sha2_256F => 49856,
            Self::Shake128S => 7856,
            Self::Shake128F => 17088,
            Self::Shake192S => 16224,
            Self::Shake192F => 35664,
            Self::Shake256S => 29792,
            Self::Shake256F => 49856,
        }
    }
    fn attribute(self) -> ParameterSetType {
        match self {
            Self::Sha2_128S => SlhDsaParameterSetType::SHA2_128S,
            Self::Sha2_128F => SlhDsaParameterSetType::SHA2_128F,
            Self::Sha2_192S => SlhDsaParameterSetType::SHA2_192S,
            Self::Sha2_192F => SlhDsaParameterSetType::SHA2_192F,
            Self::Sha2_256S => SlhDsaParameterSetType::SHA2_256S,
            Self::Sha2_256F => SlhDsaParameterSetType::SHA2_256F,
            Self::Shake128S => SlhDsaParameterSetType::SHAKE_128S,
            Self::Shake128F => SlhDsaParameterSetType::SHAKE_128F,
            Self::Shake192S => SlhDsaParameterSetType::SHAKE_192S,
            Self::Shake192F => SlhDsaParameterSetType::SHAKE_192F,
            Self::Shake256S => SlhDsaParameterSetType::SHAKE_256S,
            Self::Shake256F => SlhDsaParameterSetType::SHAKE_256F,
        }
        .into()
    }
    fn from_attribute(value: ParameterSetType) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|p| p.attribute() == value)
            .ok_or(Error::UnsupportedSigning("unknown SLH-DSA parameter set"))
    }
}
/// Original-message allocation limit for this profile (64 MiB).
pub const SLH_DSA_MAXIMUM_MESSAGE: usize = 64 * 1024 * 1024;
/// Persistent signing/verification-only pair. No seed/private value is imported.
#[derive(Clone, Copy)]
pub struct SlhDsaKeyPairRequest<'a> {
    /// Explicit standardized parameter set.
    pub parameter_set: SlhDsaParameterSet,
    /// Nonempty shared CKA_ID, at most 128 bytes. Existing pair IDs are rejected.
    pub id: &'a [u8],
    /// Nonempty shared label, at most 128 bytes.
    pub label: &'a [u8],
    /// Require context-specific authentication after each signing initialization.
    pub always_authenticate: bool,
}
impl std::fmt::Debug for SlhDsaKeyPairRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlhDsaKeyPairRequest")
            .field("parameter_set", &self.parameter_set)
            .field("always_authenticate", &self.always_authenticate)
            .finish_non_exhaustive()
    }
}
impl SlhDsaKeyPairRequest<'_> {
    /// Check identity lengths before native access. Uniqueness is not atomic
    /// against concurrent writers; provider failures may leave partial objects.
    pub fn validate(&self) -> Result<(), Error> {
        crate::key_operations::validate_secret_identity(self.id, self.label)
    }
}
/// Token randomness requirement for SLH-DSA signing. Verification ignores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlhDsaHedging {
    /// Require fresh randomness; the provider must fail if it cannot supply it.
    Required,
    /// Permit the provider's hedged or deterministic implementation.
    Preferred,
    /// Explicitly require deterministic signing.
    Deterministic,
}
impl SlhDsaHedging {
    pub(crate) fn mechanism(self) -> HedgeType {
        match self {
            Self::Required => HedgeType::Required,
            Self::Preferred => HedgeType::Preferred,
            Self::Deterministic => HedgeType::DeterministicRequired,
        }
    }
}

/// Pure SLH-DSA original-message request, with no prehash mode.
/// Debug omits message and context bytes. The expected parameter set guards against
/// selecting a key with different parameters under the same locator.
#[derive(Clone, Copy)]
pub struct SlhDsaRequest<'a> {
    /// Expected key parameter set.
    pub parameter_set: SlhDsaParameterSet,
    /// Original message, processed by CKM_SLH_DSA without external hashing.
    pub message: &'a [u8],
    /// Domain-separation context, at most 255 bytes; empty means no context.
    pub context: &'a [u8],
    /// Explicit signing randomness requirement; ignored for verification.
    pub hedging: SlhDsaHedging,
}
impl std::fmt::Debug for SlhDsaRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlhDsaRequest")
            .field("parameter_set", &self.parameter_set)
            .field("hedging", &self.hedging)
            .finish_non_exhaustive()
    }
}
impl SlhDsaRequest<'_> {
    /// Validate message/context bounds before provider access. Empty messages are valid.
    pub fn validate(&self) -> Result<(), Error> {
        if self.message.len() > SLH_DSA_MAXIMUM_MESSAGE {
            return Err(Error::InvalidParameters("SLH-DSA message exceeds 64 MiB"));
        }
        if self.context.len() > 255 {
            return Err(Error::InvalidParameters(
                "SLH-DSA context exceeds 255 bytes",
            ));
        }
        Ok(())
    }
    fn mechanism(&self) -> Mechanism<'_> {
        Mechanism::SlhDsa(SignAdditionalContext::new(
            self.hedging.mechanism(),
            if self.context.is_empty() {
                None
            } else {
                Some(self.context)
            },
        ))
    }
}

/// Pure SLH-DSA restrictions, independent of classical and ML-DSA signing policies.
#[derive(Clone, Debug)]
pub struct SlhDsaSigningPolicy {
    /// Allowed parameter sets. An empty list disables SLH-DSA signing.
    pub parameter_sets: Vec<SlhDsaParameterSet>,
}
impl Default for SlhDsaSigningPolicy {
    fn default() -> Self {
        Self {
            parameter_sets: SlhDsaParameterSet::ALL.to_vec(),
        }
    }
}
impl SlhDsaSigningPolicy {
    /// Check request context and allowed parameters without authentication or provider calls.
    pub fn validate(&self, request: &SlhDsaRequest<'_>) -> Result<(), Error> {
        request.validate()?;
        if !self.parameter_sets.contains(&request.parameter_set) {
            return Err(Error::UnsupportedSigning("SLH-DSA parameter set policy"));
        }
        Ok(())
    }
}

/// Advisory snapshot, rediscovered before each signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlhDsaCapabilities {
    /// Parameter set read from the private key.
    pub parameter_set: SlhDsaParameterSet,
    /// Key permission, allowed mechanisms and token flags/bounds all allow signing.
    pub can_sign: bool,
    /// A separate context-specific PIN is required after signing initialization.
    pub always_authenticate: bool,
}
impl SlhDsaCapabilities {
    /// Check this snapshot against the request and application policy without signing.
    pub fn validate(
        &self,
        request: &SlhDsaRequest<'_>,
        policy: &SlhDsaSigningPolicy,
    ) -> Result<(), Error> {
        policy.validate(request)?;
        if self.parameter_set != request.parameter_set {
            return Err(Error::UnsupportedSigning("SLH-DSA parameter set or policy"));
        }
        if !self.can_sign {
            return Err(Error::UnsupportedSigning(
                "SLH-DSA key or token permissions",
            ));
        }
        Ok(())
    }
}

/// Length-checked public SLH-DSA material; contains no private value or seed.
#[derive(Clone, Debug)]
pub struct SlhDsaPublicKey {
    parameter_set: SlhDsaParameterSet,
    value: Vec<u8>,
}
impl SlhDsaPublicKey {
    /// Validate FIPS 205's public-key encoding length. This does not prove key ownership.
    pub fn from_bytes(parameter_set: SlhDsaParameterSet, value: Vec<u8>) -> Result<Self, Error> {
        if value.len() != parameter_set.public_key_length() {
            return Err(Error::InvalidKeyOutput);
        }
        Ok(Self {
            parameter_set,
            value,
        })
    }
    /// Public-key parameter set.
    pub fn parameter_set(&self) -> SlhDsaParameterSet {
        self.parameter_set
    }
    /// Raw FIPS 205 public-key encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}

pub(crate) fn parameter_set(
    object: &Object<'_, '_>,
    class: ObjectClass,
) -> Result<SlhDsaParameterSet, Error> {
    if !matches!(attribute(object, AttributeType::Class, true)?, Some(Attribute::Class(value)) if value == class)
        || !matches!(
            attribute(object, AttributeType::KeyType, true)?,
            Some(Attribute::KeyType(KeyType::SLH_DSA))
        )
    {
        return Err(Error::UnsupportedSigning("SLH-DSA key class or type"));
    }
    match attribute(object, AttributeType::ParameterSet, true)? {
        Some(Attribute::ParameterSet(value)) => SlhDsaParameterSet::from_attribute(value),
        _ => Err(Error::MissingMetadata("SLH-DSA parameter set")),
    }
}

pub(crate) fn permission(object: &Object<'_, '_>, kind: AttributeType) -> Result<bool, Error> {
    match (kind, attribute(object, kind, true)?) {
        (AttributeType::Sign, Some(Attribute::Sign(value)))
        | (AttributeType::Verify, Some(Attribute::Verify(value)))
        | (AttributeType::AlwaysAuthenticate, Some(Attribute::AlwaysAuthenticate(value))) => {
            Ok(value)
        }
        _ => Err(Error::MissingMetadata("SLH-DSA key permission")),
    }
}

fn allowed(object: &Object<'_, '_>) -> Result<bool, Error> {
    allowed_mechanism(object, MechanismType::SLH_DSA)
}

pub(crate) fn allowed_mechanism(
    object: &Object<'_, '_>,
    mechanism: MechanismType,
) -> Result<bool, Error> {
    match attribute(object, AttributeType::AllowedMechanisms, false)? {
        None => Ok(true),
        Some(Attribute::AllowedMechanisms(value)) => {
            Ok(value.is_empty() || value.contains(&mechanism))
        }
        _ => Err(Error::MissingMetadata("CKA_ALLOWED_MECHANISMS")),
    }
}

pub(crate) fn mechanism_support(
    token: &Token<'_>,
    parameter: SlhDsaParameterSet,
    mechanism: MechanismType,
    flag: impl FnOnce(crate::MechanismInfo) -> bool,
) -> Result<bool, Error> {
    if !token.mechanisms()?.contains(&mechanism) {
        return Ok(false);
    }
    let info = token.mechanism_info(mechanism)?;
    Ok(
        (info.min_key_size()..=info.max_key_size()).contains(&parameter.public_key_length())
            && flag(info),
    )
}

fn capabilities(object: &Object<'_, '_>) -> Result<SlhDsaCapabilities, Error> {
    let parameter_set = parameter_set(object, ObjectClass::PRIVATE_KEY)?;
    let module = object.session.token().module.raw()?;
    Ok(SlhDsaCapabilities {
        parameter_set,
        can_sign: [Function::SignInit, Function::Sign]
            .iter()
            .all(|f| module.is_fn_supported(*f))
            && permission(object, AttributeType::Sign)?
            && allowed(object)?
            && mechanism_support(
                object.session.token(),
                parameter_set,
                MechanismType::SLH_DSA,
                |info| info.sign(),
            )?,
        always_authenticate: permission(object, AttributeType::AlwaysAuthenticate)?,
    })
}

fn verification_key(object: &Object<'_, '_>) -> Result<(SlhDsaParameterSet, bool), Error> {
    let parameter = parameter_set(object, ObjectClass::PUBLIC_KEY)?;
    let module = object.session.token().module.raw()?;
    let permitted = [Function::VerifyInit, Function::Verify]
        .iter()
        .all(|f| module.is_fn_supported(*f))
        && permission(object, AttributeType::Verify)?
        && allowed(object)?
        && mechanism_support(
            object.session.token(),
            parameter,
            MechanismType::SLH_DSA,
            |info| info.verify(),
        )?;
    Ok((parameter, permitted))
}

impl Token<'_> {
    /// Advertised key-generation choices; vendor templates can still be rejected.
    pub fn slh_dsa_generation_options(&self) -> Result<Vec<SlhDsaParameterSet>, Error> {
        if !self
            .module
            .raw()?
            .is_fn_supported(Function::GenerateKeyPair)
            || !self
                .mechanisms()?
                .contains(&MechanismType::SLH_DSA_KEY_PAIR_GEN)
        {
            return Ok(Vec::new());
        }
        let info = self.mechanism_info(MechanismType::SLH_DSA_KEY_PAIR_GEN)?;
        Ok(SlhDsaParameterSet::ALL
            .into_iter()
            .filter(|parameter| {
                info.generate_key_pair()
                    && (info.min_key_size()..=info.max_key_size())
                        .contains(&parameter.public_key_length())
            })
            .collect())
    }
}

impl<'m> Session<'m> {
    /// Generate a persistent SLH-DSA pair once, using an explicit ID and label.
    /// Private keys are sensitive and nonextractable. No seed is read or imported.
    /// Requires RW mode; partial provider effects are not rolled back or retried.
    pub fn generate_slh_dsa_key_pair(
        &mut self,
        request: &SlhDsaKeyPairRequest<'_>,
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        self.generate_slh_dsa_pair(request, &[MechanismType::SLH_DSA])
    }

    pub(crate) fn generate_slh_dsa_pair(
        &mut self,
        request: &SlhDsaKeyPairRequest<'_>,
        mechanisms: &[MechanismType],
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        request.validate()?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        let SlhDsaKeyPairRequest {
            parameter_set: parameter,
            id,
            label,
            always_authenticate,
        } = *request;
        if !self
            .token()
            .slh_dsa_generation_options()?
            .contains(&parameter)
        {
            return Err(Error::UnsupportedSigning("SLH-DSA key generation"));
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
            Attribute::Encrypt(false),
            Attribute::Wrap(false),
            Attribute::Derive(false),
            Attribute::VerifyRecover(false),
            Attribute::AllowedMechanisms(mechanisms.to_vec()),
            Attribute::ParameterSet(parameter.attribute()),
        ];
        let private = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.to_vec()),
            Attribute::Sign(true),
            Attribute::Decrypt(false),
            Attribute::Unwrap(false),
            Attribute::Derive(false),
            Attribute::SignRecover(false),
            Attribute::AllowedMechanisms(mechanisms.to_vec()),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::AlwaysAuthenticate(always_authenticate),
        ];
        let (public, private) = self.write_operation("generate SLH-DSA key pair", |raw| {
            raw.generate_key_pair(&Mechanism::SlhDsaKeyPairGen, &public, &private)
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

    /// Read the uniquely selected private key's SLH-DSA permissions and parameter set.
    pub fn slh_dsa_capabilities(
        &mut self,
        key: &PrivateKeyRef,
    ) -> Result<SlhDsaCapabilities, Error> {
        capabilities(&self.resolve(key.as_object_ref())?)
    }

    /// Read CKA_VALUE only from an explicitly public, non-private SLH-DSA public key.
    /// Requires that CKA_ALLOWED_MECHANISMS permit pure SLH-DSA, for pure SPKI export.
    /// Never reads private-key CKA_VALUE or CKA_SEED.
    pub fn slh_dsa_public_key(&mut self, key: &PublicKeyRef) -> Result<SlhDsaPublicKey, Error> {
        let object = self.resolve(key.as_object_ref())?;
        let parameter = parameter_set(&object, ObjectClass::PUBLIC_KEY)?;
        if !allowed(&object)? {
            return Err(Error::UnsupportedSigning(
                "public key excludes pure SLH-DSA",
            ));
        }
        if !matches!(
            attribute(&object, AttributeType::Private, true)?,
            Some(Attribute::Private(false))
        ) {
            return Err(Error::UnsupportedSigning("private SLH-DSA public object"));
        }
        let values = object.read_attributes(&[AttributeType::Value])?;
        match values.expose_values() {
            [Attribute::Value(value)] if value.len() == parameter.public_key_length() => {
                SlhDsaPublicKey::from_bytes(parameter, value.clone())
            }
            _ => Err(Error::MissingMetadata("SLH-DSA public value")),
        }
    }

    /// Sign the original message once after rediscovering current permissions.
    /// Context-specific PINs are borrowed after init for always-authenticate keys.
    /// Backend failures, unwinds and invalid output lengths invalidate the session.
    pub fn sign_slh_dsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &SlhDsaRequest<'_>,
        policy: &SlhDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        let result = self
            .sign_slh_dsa_once(key, request, policy, context_pin)
            .map_err(|e| {
                let unsupported = matches!(
                    &e,
                    Error::Backend { source, .. } if function_not_supported(source)
                );
                if unsupported {
                    self.healthy.set(true);
                }
                map_function_not_supported(
                    e,
                    Error::UnsupportedSigning("SLH-DSA signing unavailable"),
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
    fn sign_slh_dsa_once(
        &mut self,
        key: &PrivateKeyRef,
        request: &SlhDsaRequest<'_>,
        policy: &SlhDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        policy.validate(request)?;
        let object = self.resolve(key.as_object_ref())?;
        let capabilities = capabilities(&object)?;
        capabilities.validate(request, policy)?;
        let pin = if capabilities.always_authenticate {
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
        let mechanism = request.mechanism();
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        let signature = if capabilities.always_authenticate {
            raw.sign_init(&mechanism, object.handle)
                .map_err(|e| backend("SLH-DSA sign init", e))?;
            raw.login(UserType::ContextSpecific, pin)
                .map_err(|e| backend("SLH-DSA context login", e))?;
            raw.sign_update(request.message)
                .map_err(|e| backend("SLH-DSA sign update", e))?;
            raw.sign_final()
                .map_err(|e| backend("SLH-DSA sign final", e))?
        } else {
            raw.sign(&mechanism, object.handle, request.message)
                .map_err(|e| backend("SLH-DSA sign", e))?
        };
        if signature.len() != request.parameter_set.signature_length() {
            return Err(Error::InvalidSignature);
        }
        object.session.healthy.set(true);
        Ok(signature)
    }

    /// Verify once with a uniquely resolved public key on the token.
    /// A signature mismatch leaves the session usable; other backend failures do not.
    /// Does not prove a private-key association or certificate trust.
    pub fn verify_slh_dsa(
        &mut self,
        key: &PublicKeyRef,
        request: &SlhDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        let result = self
            .verify_slh_dsa_once(key, request, signature)
            .map_err(|e| {
                let unsupported = matches!(
                    &e,
                    Error::Backend { source, .. } if function_not_supported(source)
                );
                if unsupported {
                    self.healthy.set(true);
                }
                map_function_not_supported(
                    e,
                    Error::UnsupportedVerification("SLH-DSA verification unavailable"),
                )
            });
        if matches!(&result, Err(Error::Backend { .. } | Error::TokenChanged)) {
            self.healthy.set(false);
        }
        result
    }
    fn verify_slh_dsa_once(
        &mut self,
        key: &PublicKeyRef,
        request: &SlhDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        request.validate()?;
        if signature.len() != request.parameter_set.signature_length() {
            return Err(Error::SignatureMismatch);
        }
        let object = self.resolve(key.as_object_ref())?;
        let (parameter, permitted) = verification_key(&object)?;
        if parameter != request.parameter_set || !permitted {
            return Err(Error::UnsupportedSigning(
                "SLH-DSA verification permissions or parameter set",
            ));
        }
        let mechanism = request.mechanism();
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
            Err(error) => Err(backend("SLH-DSA verify", error)),
        }
    }
}
