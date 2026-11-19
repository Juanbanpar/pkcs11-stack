// SPDX-License-Identifier: MIT OR Apache-2.0
use cryptoki::{
    context::Function,
    error::{Error as CryptokiError, RvError},
    mechanism::Mechanism,
    session::UserType,
};

use crate::{
    Attribute, AttributeType, Error, MechanismType, Object, ObjectClass, Pin, PrivateKeyRef,
    PublicKeyRef, Session, SessionMode, error::backend, objects::attribute,
};

use super::{
    MlDsaCapabilities, MlDsaParameterSet, MlDsaPublicKey, MlDsaRequest, MlDsaSigningPolicy,
    capabilities::{allowed, capabilities, mechanism_support, parameter_set, permission},
};

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

    /// Read the public key's ML-DSA parameter set without reading key bytes.
    pub fn ml_dsa_public_parameter_set(
        &mut self,
        key: &PublicKeyRef,
    ) -> Result<MlDsaParameterSet, Error> {
        parameter_set(&self.resolve(key.as_object_ref())?, ObjectClass::PUBLIC_KEY)
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
        let pin = object
            .session
            .prepare_context_pin(capabilities.always_authenticate, context_pin)?;
        let mechanism = request.mechanism();
        let raw = object.session.begin_operation()?;
        let signature = if capabilities.always_authenticate {
            raw.sign_init(&mechanism, object.handle)
                .map_err(|e| backend("ML-DSA sign init", e))?;
            crate::session::login_with_pin(raw, UserType::ContextSpecific, pin)
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
        let raw = object.session.begin_operation()?;
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
