// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeType, Error, MacOperation, MechanismType, Object, ObjectClass, ObjectRef,
    Session, SessionMode, Token, key_operations::validate_secret_identity, signing::attribute,
};
use cryptoki::{context::Function, mechanism::Mechanism, object::KeyType};

/// Maximum single-part HMAC message size, in bytes (16 MiB).
pub const HMAC_MAXIMUM_MESSAGE: usize = 16 * 1024 * 1024;
/// Full-length SHA-2 HMAC algorithm; no truncated or legacy profile is implicit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HmacAlgorithm {
    /// HMAC-SHA-256 with a 32-byte tag.
    #[default]
    Sha256,
    /// HMAC-SHA-384 with a 48-byte tag.
    Sha384,
    /// HMAC-SHA-512 with a 64-byte tag.
    Sha512,
}
impl HmacAlgorithm {
    /// Supported full-tag algorithms; provider support is checked separately.
    pub const ALL: [Self; 3] = [Self::Sha256, Self::Sha384, Self::Sha512];
    /// Full tag length, also the generated key's length, in bytes.
    pub fn tag_length(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
    fn mechanism(self) -> Mechanism<'static> {
        match self {
            Self::Sha256 => Mechanism::Sha256Hmac,
            Self::Sha384 => Mechanism::Sha384Hmac,
            Self::Sha512 => Mechanism::Sha512Hmac,
        }
    }
    fn key_type(self) -> KeyType {
        match self {
            Self::Sha256 => KeyType::SHA256_HMAC,
            Self::Sha384 => KeyType::SHA384_HMAC,
            Self::Sha512 => KeyType::SHA512_HMAC,
        }
    }
}
impl std::fmt::Display for HmacAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sha256 => "hmac-sha256",
            Self::Sha384 => "hmac-sha384",
            Self::Sha512 => "hmac-sha512",
        })
    }
}
/// Current key length and permitted full-tag profiles for one MAC direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HmacCapabilities {
    /// Observed key length in bytes; this application accepts 16..=4096.
    pub key_length: usize,
    /// HMAC-SHA-256 is permitted and advertised.
    pub sha256: bool,
    /// HMAC-SHA-384 is permitted and advertised.
    pub sha384: bool,
    /// HMAC-SHA-512 is permitted and advertised.
    pub sha512: bool,
}
impl HmacCapabilities {
    /// Whether the algorithm was supported when queried; execution rechecks it.
    pub fn supports(self, algorithm: HmacAlgorithm) -> bool {
        match algorithm {
            HmacAlgorithm::Sha256 => self.sha256,
            HmacAlgorithm::Sha384 => self.sha384,
            HmacAlgorithm::Sha512 => self.sha512,
        }
    }
}
/// Generate a persistent, private, sensitive, nonextractable authentication key.
#[derive(Clone, Copy)]
pub struct HmacKeyRequest<'a> {
    /// Fixes the generated key length and its only allowed MAC mechanism.
    pub algorithm: HmacAlgorithm,
    /// New nonempty secret ID, at most 128 bytes; existing secret IDs are rejected.
    pub id: &'a [u8],
    /// Nonempty label, at most 128 bytes.
    pub label: &'a [u8],
}
impl HmacKeyRequest<'_> {
    /// Validate identity bounds without contacting a provider.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)
    }
}
impl std::fmt::Debug for HmacKeyRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacKeyRequest")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}
fn key_length(object: &Object<'_, '_>) -> Result<usize, Error> {
    match attribute(object, AttributeType::ValueLen, true)? {
        Some(Attribute::ValueLen(n)) if (16..=4096).contains(&usize::from(n)) => Ok(usize::from(n)),
        _ => Err(Error::UnsupportedMac),
    }
}
fn profile(
    object: &Object<'_, '_>,
    algorithm: HmacAlgorithm,
    operation: MacOperation,
) -> Result<usize, Error> {
    for (kind, expected) in [
        (
            AttributeType::Class,
            Attribute::Class(ObjectClass::SECRET_KEY),
        ),
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
    match attribute(object, AttributeType::KeyType, true)? {
        Some(Attribute::KeyType(kind))
            if kind == KeyType::GENERIC_SECRET || kind == algorithm.key_type() => {}
        _ => return Err(Error::UnsupportedMac),
    }
    let length = key_length(object)?;
    let mechanism = algorithm.mechanism().mechanism_type();
    if matches!(attribute(object, AttributeType::AllowedMechanisms, false)?, Some(Attribute::AllowedMechanisms(allowed)) if !allowed.is_empty() && !allowed.contains(&mechanism))
    {
        return Err(Error::UnsupportedMac);
    }
    let token = object.session.token();
    let raw = token.module.raw()?;
    let functions = match operation {
        MacOperation::Generate => [Function::SignInit, Function::Sign],
        MacOperation::Verify => [Function::VerifyInit, Function::Verify],
    };
    if functions.into_iter().any(|f| !raw.is_fn_supported(f))
        || !token.mechanisms()?.contains(&mechanism)
    {
        return Err(Error::UnsupportedMac);
    }
    let info = token.mechanism_info(mechanism)?;
    // The HMAC definitions do not specify units for these bounds. Providers also
    // report 0/0; enforce application bounds and let native signing check its limits.
    if !match operation {
        MacOperation::Generate => info.sign(),
        MacOperation::Verify => info.verify(),
    } {
        return Err(Error::UnsupportedMac);
    }
    Ok(length)
}
fn validate_message(message: &[u8]) -> Result<(), Error> {
    if message.len() > HMAC_MAXIMUM_MESSAGE {
        return Err(Error::InvalidParameters("HMAC message length"));
    }
    Ok(())
}
impl Token<'_> {
    /// Advertised generic-secret generation choices for hash-length HMAC keys.
    /// Generic generation bounds are in bits; CKA_VALUE_LEN remains in bytes.
    /// Does not promise template or later HMAC operation acceptance.
    pub fn hmac_generation_options(&self) -> Result<Vec<HmacAlgorithm>, Error> {
        if !self.module.raw()?.is_fn_supported(Function::GenerateKey)
            || !self
                .mechanisms()?
                .contains(&MechanismType::GENERIC_SECRET_KEY_GEN)
        {
            return Ok(vec![]);
        }
        let info = self.mechanism_info(MechanismType::GENERIC_SECRET_KEY_GEN)?;
        Ok(HmacAlgorithm::ALL
            .into_iter()
            .filter(|a| {
                info.generate()
                    && (info.min_key_size()..=info.max_key_size()).contains(&(a.tag_length() * 8))
            })
            .collect())
    }
}
impl Session<'_> {
    /// Inspect native HMAC profiles for a unique sensitive, nonextractable key.
    /// Generic or matching hash-specific HMAC keys, 16..=4096 bytes, are accepted.
    /// Missing metadata/provider errors propagate; unsupported profiles are omitted.
    pub fn hmac_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: MacOperation,
    ) -> Result<HmacCapabilities, Error> {
        let object = self.resolve(key)?;
        let supported = |algorithm| match profile(&object, algorithm, operation) {
            Ok(_) => Ok(true),
            Err(Error::UnsupportedMac) => Ok(false),
            Err(e) => Err(e),
        };
        let mut caps = HmacCapabilities {
            key_length: 0,
            sha256: supported(HmacAlgorithm::Sha256)?,
            sha384: supported(HmacAlgorithm::Sha384)?,
            sha512: supported(HmacAlgorithm::Sha512)?,
        };
        if !HmacAlgorithm::ALL.into_iter().any(|a| caps.supports(a)) {
            return Err(Error::UnsupportedMac);
        }
        caps.key_length = key_length(&object)?;
        Ok(caps)
    }
    /// Generate a full native HMAC once, with fixed-size output storage. Messages
    /// may be empty and are bounded to 16 MiB. RO sessions are permitted. No key
    /// values, truncation, software fallback or retries are exposed. Native errors,
    /// unwinds or malformed output invalidate the session; check closure.
    pub fn mac_hmac(
        &mut self,
        key: &ObjectRef,
        algorithm: HmacAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, Error> {
        validate_message(message)?;
        let object = self.resolve(key)?;
        profile(&object, algorithm, MacOperation::Generate)?;
        let mut tag = [0; 64];
        let tag = &mut tag[..algorithm.tag_length()];
        crate::mac::generate_into(&object, &algorithm.mechanism(), message, tag)?;
        Ok(tag.to_vec())
    }
    /// Verify using CKA_VERIFY and the selected native full-tag HMAC mechanism.
    /// A wrong length or completed verification mismatch returns MacMismatch and
    /// leaves the session reusable; other native failures invalidate it. Empty
    /// messages and RO sessions are allowed. Check closure before releasing results.
    pub fn verify_hmac(
        &mut self,
        key: &ObjectRef,
        algorithm: HmacAlgorithm,
        message: &[u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        validate_message(message)?;
        if tag.len() != algorithm.tag_length() {
            return Err(Error::MacMismatch);
        }
        let object = self.resolve(key)?;
        profile(&object, algorithm, MacOperation::Verify)?;
        crate::mac::verify(&object, &algorithm.mechanism(), message, tag)
    }
    /// Generate one hash-length generic secret via CKM_GENERIC_SECRET_KEY_GEN,
    /// restricted to the selected HMAC mechanism and signing/verification only.
    /// Requires RW mode; identity and generation capabilities are rechecked. No
    /// key values, fallback, retry or rollback; failures may leave persistent effects.
    pub fn generate_hmac_key(
        &mut self,
        request: &HmacKeyRequest<'_>,
    ) -> Result<Object<'_, '_>, Error> {
        request.validate()?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        if !self
            .token()
            .hmac_generation_options()?
            .contains(&request.algorithm)
        {
            return Err(Error::UnsupportedMac);
        }
        let mut template = self.new_secret_template(request.id, request.label, false)?;
        for attr in &mut template {
            match attr {
                Attribute::Sign(v) | Attribute::Verify(v) => *v = true,
                Attribute::Derive(v) => *v = false,
                _ => (),
            }
        }
        template.push(Attribute::AllowedMechanisms(vec![
            request.algorithm.mechanism().mechanism_type(),
        ]));
        template.push(Attribute::ValueLen(
            request
                .algorithm
                .tag_length()
                .try_into()
                .map_err(|_| Error::InvalidParameters("HMAC key length"))?,
        ));
        let handle = self.write_operation("generate HMAC key", |raw| {
            raw.generate_key(&Mechanism::GenericSecretKeyGen, &template)
        })?;
        Ok(Object {
            session: self,
            handle,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_identity_bounds_and_debug_do_not_expose_inputs() {
        let request = HmacKeyRequest {
            algorithm: HmacAlgorithm::Sha384,
            id: b"id-canary",
            label: b"label-canary",
        };
        request.validate().unwrap();
        assert!(!format!("{request:?}").contains("canary"));
        for (id, label) in [
            (&[][..], b"label".as_slice()),
            (&[0; 129][..], b"label".as_slice()),
            (b"id".as_slice(), &[0; 129][..]),
        ] {
            assert!(
                HmacKeyRequest {
                    id,
                    label,
                    ..request
                }
                .validate()
                .is_err()
            );
        }
        assert!(validate_message(&vec![0; HMAC_MAXIMUM_MESSAGE + 1]).is_err());
    }
}
