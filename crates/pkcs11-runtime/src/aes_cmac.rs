// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AesKeySize, Attribute, AttributeType, Error, MechanismType, ObjectClass, ObjectRef, Session,
    error::backend, signing::attribute,
};
use cryptoki::{
    context::Function,
    error::{Error as NativeError, RvError},
    mechanism::Mechanism,
    object::KeyType,
};

/// Full AES-CMAC tag length in bytes; truncation is not exposed.
pub const AES_CMAC_TAG_LENGTH: usize = 16;
/// Maximum single-part message size, in bytes (16 MiB).
pub const AES_CMAC_MAXIMUM_MESSAGE: usize = 16 * 1024 * 1024;
/// Native MAC direction, with independently checked permissions and entry points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacOperation {
    /// Requires CKA_SIGN and native SignInit/Sign.
    Generate,
    /// Requires CKA_VERIFY and native VerifyInit/Verify.
    Verify,
}
/// Advisory full-tag AES-CMAC profile, rediscovered before execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AesCmacCapabilities {
    /// AES-128, AES-192 or AES-256.
    pub key_size: AesKeySize,
}
fn capabilities(
    object: &crate::Object<'_, '_>,
    operation: MacOperation,
) -> Result<AesCmacCapabilities, Error> {
    for (kind, expected) in [
        (
            AttributeType::Class,
            Attribute::Class(ObjectClass::SECRET_KEY),
        ),
        (AttributeType::KeyType, Attribute::KeyType(KeyType::AES)),
        (AttributeType::Sensitive, Attribute::Sensitive(true)),
        (AttributeType::Extractable, Attribute::Extractable(false)),
        match operation {
            MacOperation::Generate => (AttributeType::Sign, Attribute::Sign(true)),
            MacOperation::Verify => (AttributeType::Verify, Attribute::Verify(true)),
        },
    ] {
        if attribute(object, kind, true)? != Some(expected) {
            return Err(Error::UnsupportedMac);
        }
    }
    let key_size = match attribute(object, AttributeType::ValueLen, true)? {
        Some(Attribute::ValueLen(value)) => match usize::from(value) {
            16 => AesKeySize::Bits128,
            24 => AesKeySize::Bits192,
            32 => AesKeySize::Bits256,
            _ => return Err(Error::UnsupportedMac),
        },
        _ => return Err(Error::UnsupportedMac),
    };
    if matches!(attribute(object, AttributeType::AllowedMechanisms, false)?, Some(Attribute::AllowedMechanisms(allowed)) if !allowed.is_empty() && !allowed.contains(&MechanismType::AES_CMAC))
    {
        return Err(Error::UnsupportedMac);
    }
    let token = object.session.token();
    let functions = match operation {
        MacOperation::Generate => [Function::SignInit, Function::Sign],
        MacOperation::Verify => [Function::VerifyInit, Function::Verify],
    };
    let raw = token.module.raw()?;
    if functions
        .into_iter()
        .any(|function| !raw.is_fn_supported(function))
    {
        return Err(Error::UnsupportedMac);
    }
    if !token.mechanisms()?.contains(&MechanismType::AES_CMAC) {
        return Err(Error::UnsupportedMac);
    }
    let info = token.mechanism_info(MechanismType::AES_CMAC)?;
    if !(info.min_key_size()..=info.max_key_size()).contains(&key_size.length())
        || !match operation {
            MacOperation::Generate => info.sign(),
            MacOperation::Verify => info.verify(),
        }
    {
        return Err(Error::UnsupportedMac);
    }
    Ok(AesCmacCapabilities { key_size })
}
fn validate_message(length: usize) -> Result<(), Error> {
    if length > AES_CMAC_MAXIMUM_MESSAGE {
        return Err(Error::InvalidParameters("AES CMAC message length"));
    }
    Ok(())
}
impl Session<'_> {
    /// Inspect a unique sensitive, nonextractable AES key without reading its value
    /// or performing crypto. Size, permission, allow-list, flags and pointers are checked.
    pub fn aes_cmac_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: MacOperation,
    ) -> Result<AesCmacCapabilities, Error> {
        capabilities(&self.resolve(key)?, operation)
    }
    /// Generate one full 16-byte tag using CKM_AES_CMAC. Empty messages are allowed;
    /// messages are bounded to 16 MiB. Native output uses fixed-size storage, without
    /// allocation based on provider lengths. RO sessions are permitted. No software
    /// fallback, truncation, retry or key-value access occurs. Native errors, unwinds
    /// and malformed output invalidate the session; check session closure.
    pub fn mac_aes_cmac(
        &mut self,
        key: &ObjectRef,
        message: &[u8],
    ) -> Result<[u8; AES_CMAC_TAG_LENGTH], Error> {
        validate_message(message.len())?;
        let object = self.resolve(key)?;
        capabilities(&object, MacOperation::Generate)?;
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        raw.sign_init(&Mechanism::AesCMac, object.handle)
            .map_err(|e| backend("AES CMAC init", e))?;
        let mut tag = [0; AES_CMAC_TAG_LENGTH];
        let written = raw
            .sign_initialized_into(message, &mut tag)
            .map_err(|e| backend("AES CMAC", e))?;
        if written != tag.len() {
            return Err(Error::InvalidKeyOutput);
        }
        object.session.healthy.set(true);
        Ok(tag)
    }
    /// Verify using native CKM_AES_CMAC and CKA_VERIFY, without generating a tag.
    /// Accepts messages up to 16 MiB, including empty. A non-16-byte or mismatched
    /// tag returns MacMismatch and leaves the session reusable. Other native failures
    /// invalidate it. RO sessions are permitted; no truncation or fallback occurs.
    pub fn verify_aes_cmac(
        &mut self,
        key: &ObjectRef,
        message: &[u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        validate_message(message.len())?;
        if tag.len() != AES_CMAC_TAG_LENGTH {
            return Err(Error::MacMismatch);
        }
        let object = self.resolve(key)?;
        capabilities(&object, MacOperation::Verify)?;
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        match raw.verify(&Mechanism::AesCMac, object.handle, message, tag) {
            Ok(()) => {
                object.session.healthy.set(true);
                Ok(())
            }
            Err(NativeError::Pkcs11(
                RvError::SignatureInvalid | RvError::SignatureLenRange,
                Function::Verify,
            )) => {
                object.session.healthy.set(true);
                Err(Error::MacMismatch)
            }
            Err(error) => Err(backend("AES CMAC verify", error)),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn message_bound_includes_empty_and_rejects_overflow() {
        for length in [0, 1, AES_CMAC_MAXIMUM_MESSAGE] {
            validate_message(length).unwrap();
        }
        for length in [AES_CMAC_MAXIMUM_MESSAGE + 1, usize::MAX] {
            assert!(validate_message(length).is_err());
        }
    }
}
