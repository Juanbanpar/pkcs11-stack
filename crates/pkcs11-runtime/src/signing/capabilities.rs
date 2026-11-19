// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeType, Error, MechanismType, Object, PrivateKeyRef, Session,
    objects::{attribute, key_kind},
};

use super::{KeyCapabilities, SigningMechanism};

pub(super) fn capabilities(object: &Object<'_, '_>) -> Result<KeyCapabilities, Error> {
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
pub(super) fn supported_mechanism(m: MechanismType) -> bool {
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
}
