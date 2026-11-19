// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeType, Error, KeyType, MechanismInfo, MechanismType, Object, ObjectClass,
    ObjectRef, Session,
    capability::check_key_mechanism,
    error::backend,
    objects::{attribute, key_permission},
};
use cryptoki::mechanism::Mechanism;

fn aes_length(object: &Object<'_, '_>) -> Result<usize, Error> {
    if !matches!(
        attribute(object, AttributeType::Class, true)?,
        Some(Attribute::Class(ObjectClass::SECRET_KEY))
    ) || !matches!(
        attribute(object, AttributeType::KeyType, true)?,
        Some(Attribute::KeyType(KeyType::AES))
    ) {
        return Err(Error::UnsupportedKeyOperation);
    }
    match attribute(object, AttributeType::ValueLen, true)? {
        Some(Attribute::ValueLen(length)) if [16, 24, 32].contains(&usize::from(length)) => {
            Ok(usize::from(length))
        }
        _ => Err(Error::UnsupportedKeyOperation),
    }
}

pub(super) fn check_aes_wrap_key(
    object: &Object<'_, '_>,
    permission: AttributeType,
    supported: impl FnOnce(MechanismInfo) -> bool,
) -> Result<usize, Error> {
    if !key_permission(object, permission)? {
        return Err(Error::UnsupportedKeyOperation);
    }
    let length = aes_length(object)?;
    // AES mechanism bounds are in bytes.
    check_key_mechanism(object, MechanismType::AES_KEY_WRAP, length, supported)?;
    Ok(length)
}

impl Session<'_> {
    /// Wrap an extractable AES-128/192/256 key using RFC 3394. Never reads CKA_VALUE.
    /// CKA_WRAP_WITH_TRUSTED is honored; provider wrap templates remain authoritative.
    pub fn wrap_aes_key(
        &mut self,
        wrapping: &ObjectRef,
        target: &ObjectRef,
    ) -> Result<Vec<u8>, Error> {
        let (wrapping_handle, trusted) = {
            let object = self.resolve(wrapping)?;
            check_aes_wrap_key(&object, AttributeType::Wrap, |info| info.wrap())?;
            (
                object.handle,
                matches!(
                    attribute(&object, AttributeType::Trusted, false)?,
                    Some(Attribute::Trusted(true))
                ),
            )
        };
        let target = self.resolve(target)?;
        let size = aes_length(&target)?;
        if wrapping_handle == target.handle || !key_permission(&target, AttributeType::Extractable)?
        {
            return Err(Error::UnsupportedKeyOperation);
        }
        // Unknown trust policy fails closed instead of guessing its default.
        match attribute(&target, AttributeType::WrapWithTrusted, true)? {
            Some(Attribute::WrapWithTrusted(false)) => (),
            Some(Attribute::WrapWithTrusted(true)) if trusted => (),
            _ => return Err(Error::UnsupportedKeyOperation),
        }
        let target_handle = target.handle;
        let raw = self.raw()?;
        self.healthy.set(false);
        let bytes = raw
            .wrap_key(&Mechanism::AesKeyWrap, wrapping_handle, target_handle)
            .map_err(|e| backend("wrap AES key", e))?;
        if bytes.len() != size + 8 {
            return Err(Error::InvalidKeyOutput);
        }
        self.healthy.set(true);
        Ok(bytes)
    }
    /// Unwrap one RFC 3394 AES blob as a sensitive nonextractable token key.
    /// The ciphertext length determines AES-128/192/256. No metadata is encoded in it.
    pub fn unwrap_aes_key(
        &mut self,
        unwrapping: &ObjectRef,
        wrapped: &[u8],
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        if ![24, 32, 40].contains(&wrapped.len()) {
            return Err(Error::InvalidParameters("AES wrapped input length"));
        }
        let template = self.new_secret_template(id, label, true)?;
        let object = self.resolve(unwrapping)?;
        check_aes_wrap_key(&object, AttributeType::Unwrap, |info| info.unwrap())?;
        object.session.write_operation("unwrap AES key", |raw| {
            raw.unwrap_key(&Mechanism::AesKeyWrap, object.handle, wrapped, &template)
        })?;
        Ok(())
    }
}
