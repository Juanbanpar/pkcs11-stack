// SPDX-License-Identifier: MIT OR Apache-2.0
mod ecdsa;
mod eddsa;
mod ml_dsa;
mod planning;
mod policy;
mod prehash;
mod rsa;
mod slh_dsa;
mod types;
mod verification;

use std::borrow::Cow;

use cryptoki::session::UserType;

use crate::{
    Attribute, AttributeType, Error, KeyKind, MechanismType, Object, Pin, PrivateKeyRef, Session,
    error::backend,
    objects::{attribute, key_kind},
};

pub use eddsa::{EdDsaCapabilities, EdDsaCurve, EdDsaPublicKey, EdDsaRequest};
pub use ml_dsa::{HashMlDsaCapabilities, HashMlDsaRequest, HashMlDsaSigningPolicy};
pub use ml_dsa::{
    MlDsaCapabilities, MlDsaHedging, MlDsaParameterSet, MlDsaPublicKey, MlDsaRequest,
    MlDsaSigningPolicy,
};
pub use planning::{HashLocation, SignPlan};
pub use policy::{HashingPolicy, SigningPolicy};
pub use prehash::{HashInput, PrehashAlgorithm};
pub use slh_dsa::{HashSlhDsaCapabilities, HashSlhDsaRequest, HashSlhDsaSigningPolicy};
pub use slh_dsa::{
    SLH_DSA_MAXIMUM_MESSAGE, SlhDsaCapabilities, SlhDsaHedging, SlhDsaKeyPairRequest,
    SlhDsaParameterSet, SlhDsaPublicKey, SlhDsaRequest, SlhDsaSigningPolicy,
};
pub use types::{
    DigestAlgorithm, KeyCapabilities, PssParameters, SignInput, SignRequest, SignatureAlgorithm,
    SigningMechanism,
};
pub use verification::{VerificationCapabilities, VerifyRequest};

use planning::mechanism;

fn signature_input<'a>(request: &SignRequest<'a>, hashing: HashLocation) -> Cow<'a, [u8]> {
    let mut data = match request.input {
        SignInput::Message(value) if hashing == HashLocation::Software => {
            Cow::Owned(request.digest.hash(value))
        }
        SignInput::Message(value) | SignInput::Digest(value) => Cow::Borrowed(value),
    };
    if hashing != HashLocation::Token && request.algorithm == SignatureAlgorithm::RsaPkcs1 {
        data = Cow::Owned(rsa::digest_info(request.digest, &data));
    }
    data
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
        MechanismType::SHA224_RSA_PKCS,
        MechanismType::SHA1_RSA_PKCS,
        MechanismType::SHA256_RSA_PKCS,
        MechanismType::SHA384_RSA_PKCS,
        MechanismType::SHA512_RSA_PKCS,
        MechanismType::SHA1_RSA_PKCS_PSS,
        MechanismType::SHA256_RSA_PKCS_PSS,
        MechanismType::SHA384_RSA_PKCS_PSS,
        MechanismType::SHA512_RSA_PKCS_PSS,
        MechanismType::ECDSA_SHA224,
        MechanismType::ECDSA_SHA1,
        MechanismType::ECDSA_SHA256,
        MechanismType::ECDSA_SHA384,
        MechanismType::ECDSA_SHA512,
        MechanismType::EDDSA,
    ]
    .contains(&m)
}

impl Session<'_> {
    /// Discover current signing capability from the resolved private key and token.
    pub fn key_capabilities(&mut self, key: &PrivateKeyRef) -> Result<KeyCapabilities, Error> {
        capabilities(&self.resolve(key.as_object_ref())?)
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
        let object = self.resolve(key.as_object_ref())?;
        let capabilities = capabilities(&object)?;
        let plan = capabilities.plan(request, policy)?;
        let pin = object
            .session
            .prepare_context_pin(plan.context_authentication(), context_pin)?;
        let data = signature_input(request, plan.hash_location());
        let mechanism = mechanism(request, plan.hash_location() == HashLocation::Token)?;
        let raw = object.session.begin_operation()?;
        let signature = if plan.context_authentication() {
            raw.sign_init(&mechanism, object.handle)
                .map_err(|e| backend("sign init", e))?;
            crate::session::login_with_pin(raw, UserType::ContextSpecific, pin)
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
            KeyKind::Edwards(curve) => curve.signature_length(),
            KeyKind::Montgomery(_) => 0,
        };
        if signature.len() != expected {
            return Err(Error::InvalidSignature);
        }
        object.session.healthy.set(true);
        Ok(signature)
    }
}
