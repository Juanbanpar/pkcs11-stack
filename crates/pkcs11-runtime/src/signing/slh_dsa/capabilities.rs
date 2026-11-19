// SPDX-License-Identifier: MIT OR Apache-2.0
use cryptoki::{context::Function, object::KeyType};

use crate::{
    Attribute, AttributeType, Error, MechanismType, Object, ObjectClass, Token, objects::attribute,
};

use super::{SlhDsaCapabilities, SlhDsaParameterSet};

pub(super) fn parameter_set(
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

pub(super) fn permission(object: &Object<'_, '_>, kind: AttributeType) -> Result<bool, Error> {
    match (kind, attribute(object, kind, true)?) {
        (AttributeType::Sign, Some(Attribute::Sign(value)))
        | (AttributeType::Verify, Some(Attribute::Verify(value)))
        | (AttributeType::AlwaysAuthenticate, Some(Attribute::AlwaysAuthenticate(value))) => {
            Ok(value)
        }
        _ => Err(Error::MissingMetadata("SLH-DSA key permission")),
    }
}

pub(super) fn allowed(object: &Object<'_, '_>) -> Result<bool, Error> {
    allowed_mechanism(object, MechanismType::SLH_DSA)
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

pub(super) fn mechanism_support(
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

pub(super) fn capabilities(object: &Object<'_, '_>) -> Result<SlhDsaCapabilities, Error> {
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

pub(super) fn verification_key(
    object: &Object<'_, '_>,
) -> Result<(SlhDsaParameterSet, bool), Error> {
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
