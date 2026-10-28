// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AesKeySize, Attribute, AttributeType, Error, MechanismType, ObjectClass, ObjectRef, Session,
    signing::attribute,
};
use cryptoki::{context::Function, mechanism::Mechanism, object::KeyType};

/// Full AES-CMAC tag length in bytes.
pub const AES_CMAC_TAG_LENGTH: usize = 16;
/// Maximum single-part message size, in bytes (16 MiB).
pub const AES_CMAC_MAXIMUM_MESSAGE: usize = 16 * 1024 * 1024;
/// Explicit native AES-CMAC tag profile. Existing calls use Full.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AesCmacProfile {
    /// CKM_AES_CMAC with its full 16-byte tag and no parameter.
    #[default]
    Full,
    /// CKM_AES_CMAC_GENERAL with an explicit byte length, bounded to 8..=16.
    General {
        /// Requested tag length in bytes.
        tag_length: usize,
    },
}
impl AesCmacProfile {
    /// Supported profiles, preferring full tags and longer general tags.
    pub const ALL: [Self; 10] = [
        Self::Full,
        Self::General { tag_length: 16 },
        Self::General { tag_length: 15 },
        Self::General { tag_length: 14 },
        Self::General { tag_length: 13 },
        Self::General { tag_length: 12 },
        Self::General { tag_length: 11 },
        Self::General { tag_length: 10 },
        Self::General { tag_length: 9 },
        Self::General { tag_length: 8 },
    ];
    /// Requested tag length; validate before allocating or calling a provider.
    pub fn tag_length(self) -> usize {
        match self {
            Self::Full => 16,
            Self::General { tag_length } => tag_length,
        }
    }
    /// Enforce this application's 64-bit minimum tag policy without I/O.
    pub fn validate(self) -> Result<(), Error> {
        if (8..=16).contains(&self.tag_length()) {
            Ok(())
        } else {
            Err(Error::InvalidParameters("AES CMAC tag length"))
        }
    }
    fn mechanism(self) -> MechanismType {
        match self {
            Self::Full => MechanismType::AES_CMAC,
            Self::General { .. } => MechanismType::AES_CMAC_GENERAL,
        }
    }
    fn parameters(self) -> Mechanism<'static> {
        match self {
            Self::Full => Mechanism::AesCMac,
            Self::General { tag_length } => Mechanism::AesCMacGeneral(
                cryptoki::mechanism::misc::MacGeneralParams::new(tag_length),
            ),
        }
    }
}
impl std::fmt::Display for AesCmacProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => f.write_str("16 bytes — full tag"),
            Self::General { tag_length } => write!(f, "{tag_length} bytes — general profile"),
        }
    }
}
/// Advisory native AES-CMAC profiles for one selected key and operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AesCmacOptions {
    /// Observed AES key size.
    pub key_size: AesKeySize,
    /// CKM_AES_CMAC is permitted and advertised.
    pub full: bool,
    /// CKM_AES_CMAC_GENERAL is permitted and advertised; individual lengths remain advisory.
    pub general: bool,
}
impl AesCmacOptions {
    /// Whether the inspected native profile is permitted; execution rechecks it.
    pub fn supports(self, profile: AesCmacProfile) -> bool {
        profile.validate().is_ok()
            && match profile {
                AesCmacProfile::Full => self.full,
                AesCmacProfile::General { .. } => self.general,
            }
    }
}
/// Native MAC direction, with independently checked permissions and entry points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacOperation {
    /// Requires CKA_SIGN and native signing functions.
    Generate,
    /// Requires CKA_VERIFY and native verification functions.
    Verify,
}
impl MacOperation {
    pub(crate) fn functions(self, multipart: bool) -> &'static [Function] {
        match (self, multipart) {
            (Self::Generate, false) => &[Function::SignInit, Function::Sign],
            (Self::Verify, false) => &[Function::VerifyInit, Function::Verify],
            (Self::Generate, true) => &[
                Function::SignInit,
                Function::SignUpdate,
                Function::SignFinal,
            ],
            (Self::Verify, true) => &[
                Function::VerifyInit,
                Function::VerifyUpdate,
                Function::VerifyFinal,
            ],
        }
    }
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
    profile: AesCmacProfile,
) -> Result<AesCmacCapabilities, Error> {
    check_capabilities(object, operation, profile, false)
}
fn check_capabilities(
    object: &crate::Object<'_, '_>,
    operation: MacOperation,
    profile: AesCmacProfile,
    multipart: bool,
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
    if matches!(attribute(object, AttributeType::AllowedMechanisms, false)?, Some(Attribute::AllowedMechanisms(allowed)) if !allowed.is_empty() && !allowed.contains(&profile.mechanism()))
    {
        return Err(Error::UnsupportedMac);
    }
    let token = object.session.token();
    let raw = token.module.raw()?;
    if operation
        .functions(multipart)
        .iter()
        .any(|&f| !raw.is_fn_supported(f))
    {
        return Err(Error::UnsupportedMac);
    }
    if !token.mechanisms()?.contains(&profile.mechanism()) {
        return Err(Error::UnsupportedMac);
    }
    let info = token.mechanism_info(profile.mechanism())?;
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
    /// Begin native multipart AES-CMAC generation with an explicit full/general
    /// profile. Requires init/update/final functions and signing permission. Input
    /// is not retained or limited to the single-part 16 MiB bound; callers enforce
    /// their budget. RO sessions are allowed. Abandonment discards the session.
    pub fn start_aes_cmac(
        &mut self,
        key: &ObjectRef,
        profile: AesCmacProfile,
    ) -> Result<crate::MacGeneration<'_>, Error> {
        profile.validate()?;
        let object = self.resolve(key)?;
        check_capabilities(&object, MacOperation::Generate, profile, true)?;
        crate::MacGeneration::start(&object, &profile.parameters(), profile.tag_length())
    }
    /// Begin native multipart AES-CMAC verification with independent CKA_VERIFY
    /// permission and init/update/final checks. The same input and lifecycle bounds
    /// as start_aes_cmac apply; no host tag generation or fallback occurs.
    pub fn start_aes_cmac_verification(
        &mut self,
        key: &ObjectRef,
        profile: AesCmacProfile,
    ) -> Result<crate::MacVerification<'_>, Error> {
        profile.validate()?;
        let object = self.resolve(key)?;
        check_capabilities(&object, MacOperation::Verify, profile, true)?;
        crate::MacVerification::start(&object, &profile.parameters(), profile.tag_length())
    }
    /// Inspect a unique sensitive, nonextractable AES key without reading its value
    /// or performing crypto. Size, permission, allow-list, flags and pointers are checked.
    pub fn aes_cmac_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: MacOperation,
    ) -> Result<AesCmacCapabilities, Error> {
        capabilities(&self.resolve(key)?, operation, AesCmacProfile::Full)
    }
    /// Inspect a native full or general profile, including explicit tag bounds.
    pub fn aes_cmac_capabilities_with_profile(
        &mut self,
        key: &ObjectRef,
        operation: MacOperation,
        profile: AesCmacProfile,
    ) -> Result<AesCmacCapabilities, Error> {
        profile.validate()?;
        capabilities(&self.resolve(key)?, operation, profile)
    }
    /// Inspect both native profiles, omitting unsupported ones while preserving
    /// selection/provider errors. Does not read key values or generate a tag.
    pub fn aes_cmac_options(
        &mut self,
        key: &ObjectRef,
        operation: MacOperation,
    ) -> Result<AesCmacOptions, Error> {
        let object = self.resolve(key)?;
        let inspect = |profile| match capabilities(&object, operation, profile) {
            Ok(caps) => Ok(Some(caps)),
            Err(Error::UnsupportedMac) => Ok(None),
            Err(error) => Err(error),
        };
        let full = inspect(AesCmacProfile::Full)?;
        let general = inspect(AesCmacProfile::General { tag_length: 16 })?;
        let key_size = full.or(general).ok_or(Error::UnsupportedMac)?.key_size;
        Ok(AesCmacOptions {
            key_size,
            full: full.is_some(),
            general: general.is_some(),
        })
    }
    /// Generate an explicitly selected full or general tag. General tags use native
    /// CKM_AES_CMAC_GENERAL; no software truncation or fallback occurs. General
    /// lengths are 8..=16 bytes; agree on one length for the key's lifetime.
    /// Messages are bounded to 16 MiB. Storage is fixed at 16 bytes, and native
    /// length mismatches/errors invalidate the session. RO mode is permitted.
    pub fn mac_aes_cmac_with_profile(
        &mut self,
        key: &ObjectRef,
        message: &[u8],
        profile: AesCmacProfile,
    ) -> Result<Vec<u8>, Error> {
        profile.validate()?;
        validate_message(message.len())?;
        let object = self.resolve(key)?;
        capabilities(&object, MacOperation::Generate, profile)?;
        let mut tag = [0; AES_CMAC_TAG_LENGTH];
        let tag = &mut tag[..profile.tag_length()];
        crate::mac::generate_into(&object, &profile.parameters(), message, tag)?;
        Ok(tag.to_vec())
    }
    /// Verify with the explicitly selected native profile and exact tag length.
    /// A length/content mismatch leaves the session reusable. Other native errors
    /// invalidate it. No full-tag regeneration, software truncation or fallback.
    pub fn verify_aes_cmac_with_profile(
        &mut self,
        key: &ObjectRef,
        message: &[u8],
        tag: &[u8],
        profile: AesCmacProfile,
    ) -> Result<(), Error> {
        profile.validate()?;
        validate_message(message.len())?;
        if tag.len() != profile.tag_length() {
            return Err(Error::MacMismatch);
        }
        let object = self.resolve(key)?;
        capabilities(&object, MacOperation::Verify, profile)?;
        crate::mac::verify(&object, &profile.parameters(), message, tag)
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
        capabilities(&object, MacOperation::Generate, AesCmacProfile::Full)?;
        let mut tag = [0; AES_CMAC_TAG_LENGTH];
        crate::mac::generate_into(&object, &Mechanism::AesCMac, message, &mut tag)?;
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
        capabilities(&object, MacOperation::Verify, AesCmacProfile::Full)?;
        crate::mac::verify(&object, &Mechanism::AesCMac, message, tag)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn general_tag_lengths_are_bounded_before_native_use() {
        for profile in AesCmacProfile::ALL {
            profile.validate().unwrap();
        }
        for tag_length in [0, 1, 7, 17, usize::MAX] {
            assert!(AesCmacProfile::General { tag_length }.validate().is_err());
        }
    }
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
