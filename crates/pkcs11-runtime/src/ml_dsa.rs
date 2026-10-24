// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeType, Error, MechanismType, Object, ObjectClass, Pin, PrivateKeyRef,
    PublicKeyRef, Session, SessionMode, Token, error::backend, signing::attribute,
};
use cryptoki::{
    context::Function,
    error::{Error as CryptokiError, RvError},
    mechanism::{
        Mechanism,
        dsa::{HedgeType, SignAdditionalContext},
    },
    object::{KeyType, MlDsaParameterSetType, ParameterSetType},
    session::UserType,
};

/// FIPS 204 parameter sets. Mechanism key-size bounds use public-key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsaParameterSet {
    /// ML-DSA-44 (NIST security category 2).
    MlDsa44,
    /// ML-DSA-65 (NIST security category 3).
    MlDsa65,
    /// ML-DSA-87 (NIST security category 5).
    MlDsa87,
}
impl MlDsaParameterSet {
    /// Exact encoded public-key length, in bytes.
    pub fn public_key_length(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }
    /// Exact signature length, in bytes.
    pub fn signature_length(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
    fn attribute(self) -> ParameterSetType {
        match self {
            Self::MlDsa44 => MlDsaParameterSetType::ML_DSA_44,
            Self::MlDsa65 => MlDsaParameterSetType::ML_DSA_65,
            Self::MlDsa87 => MlDsaParameterSetType::ML_DSA_87,
        }
        .into()
    }
    fn from_attribute(value: ParameterSetType) -> Result<Self, Error> {
        [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87]
            .into_iter()
            .find(|parameter| parameter.attribute() == value)
            .ok_or(Error::UnsupportedSigning("unknown ML-DSA parameter set"))
    }
}

/// Token randomness requirement for ML-DSA signing. Verification ignores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsaHedging {
    /// Require fresh randomness; the provider must fail if it cannot supply it.
    Required,
    /// Permit the provider's hedged or deterministic implementation.
    Preferred,
    /// Explicitly require deterministic signing.
    Deterministic,
}
impl MlDsaHedging {
    fn mechanism(self) -> HedgeType {
        match self {
            Self::Required => HedgeType::Required,
            Self::Preferred => HedgeType::Preferred,
            Self::Deterministic => HedgeType::DeterministicRequired,
        }
    }
}

/// Pure ML-DSA message request, with no prehash or external-mu mode.
/// Debug omits message and context bytes. The expected parameter set guards against
/// selecting a key with different parameters under the same locator.
#[derive(Clone, Copy)]
pub struct MlDsaRequest<'a> {
    /// Expected key parameter set.
    pub parameter_set: MlDsaParameterSet,
    /// Original message, processed by CKM_ML_DSA without external hashing.
    pub message: &'a [u8],
    /// Domain-separation context, at most 255 bytes; empty means no context.
    pub context: &'a [u8],
    /// Explicit signing randomness requirement; ignored for verification.
    pub hedging: MlDsaHedging,
}
impl std::fmt::Debug for MlDsaRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaRequest")
            .field("parameter_set", &self.parameter_set)
            .field("hedging", &self.hedging)
            .finish_non_exhaustive()
    }
}
impl MlDsaRequest<'_> {
    /// Validate context length before provider access. Empty messages are valid.
    pub fn validate(&self) -> Result<(), Error> {
        if self.context.len() > 255 {
            return Err(Error::InvalidParameters("ML-DSA context exceeds 255 bytes"));
        }
        Ok(())
    }
    fn mechanism(&self) -> Mechanism<'_> {
        Mechanism::MlDsa(SignAdditionalContext::new(
            self.hedging.mechanism(),
            if self.context.is_empty() {
                None
            } else {
                Some(self.context)
            },
        ))
    }
}

/// ML-DSA signing restrictions, independent of the classical digest-based policy.
#[derive(Clone, Debug)]
pub struct MlDsaSigningPolicy {
    /// Allowed parameter sets. An empty list disables ML-DSA signing.
    pub parameter_sets: Vec<MlDsaParameterSet>,
}
impl Default for MlDsaSigningPolicy {
    fn default() -> Self {
        Self {
            parameter_sets: vec![
                MlDsaParameterSet::MlDsa44,
                MlDsaParameterSet::MlDsa65,
                MlDsaParameterSet::MlDsa87,
            ],
        }
    }
}
impl MlDsaSigningPolicy {
    /// Check request context and allowed parameters without authentication or provider calls.
    pub fn validate(&self, request: &MlDsaRequest<'_>) -> Result<(), Error> {
        request.validate()?;
        if !self.parameter_sets.contains(&request.parameter_set) {
            return Err(Error::UnsupportedSigning("ML-DSA parameter set policy"));
        }
        Ok(())
    }
}

/// Advisory snapshot, rediscovered before each signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlDsaCapabilities {
    /// Parameter set read from the private key.
    pub parameter_set: MlDsaParameterSet,
    /// Key permission, allowed mechanisms and token flags/bounds all allow signing.
    pub can_sign: bool,
    /// A separate context-specific PIN is required after signing initialization.
    pub always_authenticate: bool,
}
impl MlDsaCapabilities {
    /// Check this snapshot against the request and application policy without signing.
    pub fn validate(
        &self,
        request: &MlDsaRequest<'_>,
        policy: &MlDsaSigningPolicy,
    ) -> Result<(), Error> {
        policy.validate(request)?;
        if self.parameter_set != request.parameter_set {
            return Err(Error::UnsupportedSigning("ML-DSA parameter set or policy"));
        }
        if !self.can_sign {
            return Err(Error::UnsupportedSigning("ML-DSA key or token permissions"));
        }
        Ok(())
    }
}

/// Length-checked public ML-DSA material; contains no private value or seed.
#[derive(Clone, Debug)]
pub struct MlDsaPublicKey {
    parameter_set: MlDsaParameterSet,
    value: Vec<u8>,
}
impl MlDsaPublicKey {
    /// Validate FIPS 204's public-key encoding length. This does not prove key ownership.
    pub fn from_bytes(parameter_set: MlDsaParameterSet, value: Vec<u8>) -> Result<Self, Error> {
        if value.len() != parameter_set.public_key_length() {
            return Err(Error::InvalidKeyOutput);
        }
        Ok(Self {
            parameter_set,
            value,
        })
    }
    /// Public-key parameter set.
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }
    /// Raw FIPS 204 public-key encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}

fn parameter_set(object: &Object<'_, '_>, class: ObjectClass) -> Result<MlDsaParameterSet, Error> {
    if !matches!(attribute(object, AttributeType::Class, true)?, Some(Attribute::Class(value)) if value == class)
        || !matches!(
            attribute(object, AttributeType::KeyType, true)?,
            Some(Attribute::KeyType(KeyType::ML_DSA))
        )
    {
        return Err(Error::UnsupportedSigning("ML-DSA key class or type"));
    }
    match attribute(object, AttributeType::ParameterSet, true)? {
        Some(Attribute::ParameterSet(value)) => MlDsaParameterSet::from_attribute(value),
        _ => Err(Error::MissingMetadata("ML-DSA parameter set")),
    }
}

fn permission(object: &Object<'_, '_>, kind: AttributeType) -> Result<bool, Error> {
    match (kind, attribute(object, kind, true)?) {
        (AttributeType::Sign, Some(Attribute::Sign(value)))
        | (AttributeType::Verify, Some(Attribute::Verify(value)))
        | (AttributeType::AlwaysAuthenticate, Some(Attribute::AlwaysAuthenticate(value))) => {
            Ok(value)
        }
        _ => Err(Error::MissingMetadata("ML-DSA key permission")),
    }
}

fn allowed(object: &Object<'_, '_>) -> Result<bool, Error> {
    match attribute(object, AttributeType::AllowedMechanisms, false)? {
        None => Ok(true),
        Some(Attribute::AllowedMechanisms(value)) => {
            Ok(value.is_empty() || value.contains(&MechanismType::ML_DSA))
        }
        _ => Err(Error::MissingMetadata("CKA_ALLOWED_MECHANISMS")),
    }
}

fn mechanism_support(
    token: &Token<'_>,
    parameter: MlDsaParameterSet,
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

fn capabilities(object: &Object<'_, '_>) -> Result<MlDsaCapabilities, Error> {
    let parameter_set = parameter_set(object, ObjectClass::PRIVATE_KEY)?;
    Ok(MlDsaCapabilities {
        parameter_set,
        can_sign: permission(object, AttributeType::Sign)?
            && allowed(object)?
            && mechanism_support(
                object.session.token(),
                parameter_set,
                MechanismType::ML_DSA,
                |info| info.sign(),
            )?,
        always_authenticate: permission(object, AttributeType::AlwaysAuthenticate)?,
    })
}

impl Token<'_> {
    /// Advertised key-generation choices; vendor templates can still be rejected.
    pub fn ml_dsa_generation_options(&self) -> Result<Vec<MlDsaParameterSet>, Error> {
        if !self
            .mechanisms()?
            .contains(&MechanismType::ML_DSA_KEY_PAIR_GEN)
        {
            return Ok(Vec::new());
        }
        let info = self.mechanism_info(MechanismType::ML_DSA_KEY_PAIR_GEN)?;
        Ok([
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ]
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
    /// Generate a persistent ML-DSA pair once, using an explicit ID and label.
    /// Private keys are sensitive and nonextractable. No seed is read or imported.
    /// Requires RW mode; partial provider effects are not rolled back or retried.
    pub fn generate_ml_dsa_key_pair(
        &mut self,
        parameter: MlDsaParameterSet,
        id: &[u8],
        label: &[u8],
        always_authenticate: bool,
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        if id.is_empty() {
            return Err(Error::InvalidParameters("key ID must not be empty"));
        }
        if !self
            .token()
            .ml_dsa_generation_options()?
            .contains(&parameter)
        {
            return Err(Error::UnsupportedSigning("ML-DSA key generation"));
        }
        let public = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.to_vec()),
            Attribute::Verify(true),
            Attribute::ParameterSet(parameter.attribute()),
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
        ];
        let (public, private) = self.write_operation("generate ML-DSA key pair", |raw| {
            raw.generate_key_pair(&Mechanism::MlDsaKeyPairGen, &public, &private)
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

    /// Read the uniquely selected private key's ML-DSA permissions and parameter set.
    pub fn ml_dsa_capabilities(&mut self, key: &PrivateKeyRef) -> Result<MlDsaCapabilities, Error> {
        capabilities(&self.resolve(key.as_object_ref())?)
    }

    /// Read CKA_VALUE only from an explicitly public, non-private ML-DSA public key.
    /// Never reads private-key CKA_VALUE or CKA_SEED.
    pub fn ml_dsa_public_key(&mut self, key: &PublicKeyRef) -> Result<MlDsaPublicKey, Error> {
        let object = self.resolve(key.as_object_ref())?;
        let parameter = parameter_set(&object, ObjectClass::PUBLIC_KEY)?;
        if !matches!(
            attribute(&object, AttributeType::Private, true)?,
            Some(Attribute::Private(false))
        ) {
            return Err(Error::UnsupportedSigning("private ML-DSA public object"));
        }
        match attribute(&object, AttributeType::Value, true)? {
            Some(Attribute::Value(value)) => MlDsaPublicKey::from_bytes(parameter, value),
            _ => Err(Error::MissingMetadata("ML-DSA public value")),
        }
    }

    /// Sign the original message once after rediscovering current permissions.
    /// Context-specific PINs are borrowed after init for always-authenticate keys.
    /// Backend failures, unwinds and invalid output lengths invalidate the session.
    pub fn sign_ml_dsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &MlDsaRequest<'_>,
        policy: &MlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        let result = self.sign_ml_dsa_once(key, request, policy, context_pin);
        if matches!(
            &result,
            Err(Error::Backend { .. } | Error::TokenChanged | Error::InvalidSignature)
        ) {
            self.healthy.set(false);
        }
        result
    }
    fn sign_ml_dsa_once(
        &mut self,
        key: &PrivateKeyRef,
        request: &MlDsaRequest<'_>,
        policy: &MlDsaSigningPolicy,
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
                .map_err(|e| backend("ML-DSA sign init", e))?;
            raw.login(UserType::ContextSpecific, pin)
                .map_err(|e| backend("ML-DSA context login", e))?;
            raw.sign_update(request.message)
                .map_err(|e| backend("ML-DSA sign update", e))?;
            raw.sign_final()
                .map_err(|e| backend("ML-DSA sign final", e))?
        } else {
            raw.sign(&mechanism, object.handle, request.message)
                .map_err(|e| backend("ML-DSA sign", e))?
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
    pub fn verify_ml_dsa(
        &mut self,
        key: &PublicKeyRef,
        request: &MlDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        let result = self.verify_ml_dsa_once(key, request, signature);
        if matches!(&result, Err(Error::Backend { .. } | Error::TokenChanged)) {
            self.healthy.set(false);
        }
        result
    }
    fn verify_ml_dsa_once(
        &mut self,
        key: &PublicKeyRef,
        request: &MlDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        request.validate()?;
        if signature.len() != request.parameter_set.signature_length() {
            return Err(Error::SignatureMismatch);
        }
        let object = self.resolve(key.as_object_ref())?;
        let parameter = parameter_set(&object, ObjectClass::PUBLIC_KEY)?;
        if parameter != request.parameter_set
            || !permission(&object, AttributeType::Verify)?
            || !allowed(&object)?
            || !mechanism_support(
                object.session.token(),
                parameter,
                MechanismType::ML_DSA,
                |info| info.verify(),
            )?
        {
            return Err(Error::UnsupportedSigning(
                "ML-DSA verification permissions or parameter set",
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
            Err(error) => Err(backend("ML-DSA verify", error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_bounds_and_debug_redaction() {
        let request = MlDsaRequest {
            parameter_set: MlDsaParameterSet::MlDsa44,
            message: b"message-redaction-canary",
            context: b"context-redaction-canary",
            hedging: MlDsaHedging::Required,
        };
        assert!(!format!("{request:?}").contains("canary"));
        for length in [0, 255] {
            let context = vec![0; length];
            let bounded = MlDsaRequest {
                context: &context,
                message: b"",
                ..request
            };
            assert!(bounded.validate().is_ok());
        }
        let request = MlDsaRequest {
            context: &[0; 256],
            ..request
        };
        assert!(matches!(
            request.validate(),
            Err(Error::InvalidParameters(_))
        ));
    }

    #[test]
    fn policies_and_capabilities_reject_disallowed_or_replaced_keys() {
        let request = MlDsaRequest {
            parameter_set: MlDsaParameterSet::MlDsa65,
            message: b"message",
            context: b"",
            hedging: MlDsaHedging::Preferred,
        };
        let mut caps = MlDsaCapabilities {
            parameter_set: MlDsaParameterSet::MlDsa65,
            can_sign: true,
            always_authenticate: true,
        };
        let policy = MlDsaSigningPolicy::default();
        caps.validate(&request, &policy).unwrap();
        assert!(matches!(
            caps.validate(
                &request,
                &MlDsaSigningPolicy {
                    parameter_sets: vec![]
                }
            ),
            Err(Error::UnsupportedSigning(_))
        ));
        caps.parameter_set = MlDsaParameterSet::MlDsa44;
        assert!(matches!(
            caps.validate(&request, &policy),
            Err(Error::UnsupportedSigning(_))
        ));
        caps.parameter_set = MlDsaParameterSet::MlDsa65;
        caps.can_sign = false;
        assert!(matches!(
            caps.validate(&request, &policy),
            Err(Error::UnsupportedSigning(_))
        ));
    }

    #[test]
    fn public_key_lengths_and_unknown_parameters_fail_closed() {
        for parameter in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ] {
            assert!(
                MlDsaPublicKey::from_bytes(parameter, vec![0; parameter.public_key_length()])
                    .is_ok()
            );
            for length in [
                0,
                parameter.public_key_length() - 1,
                parameter.public_key_length() + 1,
            ] {
                assert!(matches!(
                    MlDsaPublicKey::from_bytes(parameter, vec![0; length]),
                    Err(Error::InvalidKeyOutput)
                ));
            }
        }
        let unknown = ParameterSetType::try_from(cryptoki::types::Ulong::new(0xFFFF)).unwrap();
        assert!(matches!(
            MlDsaParameterSet::from_attribute(unknown),
            Err(Error::UnsupportedSigning(_))
        ));
    }
}
