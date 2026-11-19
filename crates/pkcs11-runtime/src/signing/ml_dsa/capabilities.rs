// SPDX-License-Identifier: MIT OR Apache-2.0
use cryptoki::object::KeyType;

use crate::{
    Attribute, AttributeType, Error, MechanismType, Object, ObjectClass, Token, objects::attribute,
};

use super::{MlDsaCapabilities, MlDsaParameterSet};

pub(super) fn parameter_set(
    object: &Object<'_, '_>,
    class: ObjectClass,
) -> Result<MlDsaParameterSet, Error> {
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

pub(super) fn permission(object: &Object<'_, '_>, kind: AttributeType) -> Result<bool, Error> {
    match (kind, attribute(object, kind, true)?) {
        (AttributeType::Sign, Some(Attribute::Sign(value)))
        | (AttributeType::Verify, Some(Attribute::Verify(value)))
        | (AttributeType::AlwaysAuthenticate, Some(Attribute::AlwaysAuthenticate(value))) => {
            Ok(value)
        }
        _ => Err(Error::MissingMetadata("ML-DSA key permission")),
    }
}

pub(super) fn allowed_mechanism(
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

pub(super) fn allowed(object: &Object<'_, '_>) -> Result<bool, Error> {
    allowed_mechanism(object, MechanismType::ML_DSA)
}

pub(super) fn mechanism_support(
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

pub(super) fn capabilities(object: &Object<'_, '_>) -> Result<MlDsaCapabilities, Error> {
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
