// SPDX-License-Identifier: MIT OR Apache-2.0
use cryptoki::{
    context::Function,
    error::{Error as CryptokiError, RvError},
    mechanism::Mechanism,
    session::UserType,
};

use crate::{
    Attribute, AttributeType, Error, MechanismType, Object, ObjectClass, Pin, PrivateKeyRef,
    PublicKeyRef, Session, SessionMode,
    error::{backend, function_not_supported, map_function_not_supported},
    objects::attribute,
};

use super::{
    SlhDsaCapabilities, SlhDsaKeyPairRequest, SlhDsaParameterSet, SlhDsaPublicKey, SlhDsaRequest,
    SlhDsaSigningPolicy,
    capabilities::{allowed, capabilities, parameter_set, verification_key},
};

impl Object<'_, '_> {
    /// Read the public value of this non-private SLH-DSA public key.
    pub fn slh_dsa_public_key(&self) -> Result<SlhDsaPublicKey, Error> {
        let parameter = parameter_set(self, ObjectClass::PUBLIC_KEY)?;
        if !allowed(self)? {
            return Err(Error::UnsupportedSigning(
                "public key excludes pure SLH-DSA",
            ));
        }
        if !matches!(
            attribute(self, AttributeType::Private, true)?,
            Some(Attribute::Private(false))
        ) {
            return Err(Error::UnsupportedSigning("private SLH-DSA public object"));
        }
        let values = self.read_attributes(&[AttributeType::Value])?;
        match values.expose_values() {
            [Attribute::Value(value)] if value.len() == parameter.public_key_length() => {
                SlhDsaPublicKey::from_bytes(parameter, value.clone())
            }
            _ => Err(Error::MissingMetadata("SLH-DSA public value")),
        }
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

    /// Generate a persistent HashSLH-DSA-only signing pair.
    ///
    /// The allowed-mechanism list contains the raw prehash mechanism and every
    /// combined SHA-2/SHA-3 message mechanism. Pure SLH-DSA and SHAKE prehash
    /// remain excluded so callers cannot silently switch profiles.
    pub fn generate_hash_slh_dsa_key_pair(
        &mut self,
        request: &SlhDsaKeyPairRequest<'_>,
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        self.generate_slh_dsa_pair(
            request,
            &[
                MechanismType::HASH_SLH_DSA,
                MechanismType::HASH_SLH_DSA_SHA224,
                MechanismType::HASH_SLH_DSA_SHA256,
                MechanismType::HASH_SLH_DSA_SHA384,
                MechanismType::HASH_SLH_DSA_SHA512,
                MechanismType::HASH_SLH_DSA_SHA3_224,
                MechanismType::HASH_SLH_DSA_SHA3_256,
                MechanismType::HASH_SLH_DSA_SHA3_384,
                MechanismType::HASH_SLH_DSA_SHA3_512,
            ],
        )
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

    /// Read the public key's SLH-DSA parameter set without reading key bytes.
    pub fn slh_dsa_public_parameter_set(
        &mut self,
        key: &PublicKeyRef,
    ) -> Result<SlhDsaParameterSet, Error> {
        parameter_set(&self.resolve(key.as_object_ref())?, ObjectClass::PUBLIC_KEY)
    }

    /// Read CKA_VALUE only from an explicitly public, non-private SLH-DSA public key.
    /// Requires that CKA_ALLOWED_MECHANISMS permit pure SLH-DSA, for pure SPKI export.
    /// Never reads private-key CKA_VALUE or CKA_SEED.
    pub fn slh_dsa_public_key(&mut self, key: &PublicKeyRef) -> Result<SlhDsaPublicKey, Error> {
        self.resolve(key.as_object_ref())?.slh_dsa_public_key()
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
        let pin = object
            .session
            .prepare_context_pin(capabilities.always_authenticate, context_pin)?;
        let mechanism = request.mechanism();
        let raw = object.session.begin_operation()?;
        let signature = if capabilities.always_authenticate {
            raw.sign_init(&mechanism, object.handle)
                .map_err(|e| backend("SLH-DSA sign init", e))?;
            crate::session::login_with_pin(raw, UserType::ContextSpecific, pin)
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
            Err(error) => Err(backend("SLH-DSA verify", error)),
        }
    }
}
