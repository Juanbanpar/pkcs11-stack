// SPDX-License-Identifier: MIT OR Apache-2.0
//! Token MAC operations: full-tag HMAC (SHA-1/SHA-2) and AES-CMAC.
//!
//! General-length HMAC/CMAC, SHA-3 HMAC and BLAKE2 have no typed mechanism in
//! published `cryptoki` 0.12.1 and are therefore not executable here.

use crate::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, Attribute, AttributeType, Error, MechanismType,
    Object, ObjectClass, ObjectRef, Session, SessionMode, Token,
    error::{backend, function_not_supported, map_function_not_supported},
    key_operations::validate_secret_identity,
    signing::attribute,
};
use cryptoki::{
    context::Function,
    error::{Error as NativeError, RvError},
    mechanism::Mechanism,
    object::KeyType,
};
use std::ffi::c_ulong;

/// Maximum single-part MAC input, in bytes (64 MiB).
pub const MAC_MAXIMUM_INPUT: usize = 64 * 1024 * 1024;

/// Published `cryptoki` 0.12.1 maps `KeyType::SHA224_HMAC`, `SHA384_HMAC` and
/// `SHA512_HMAC` to the SHA-256 key-type value. The OASIS numeric values are
/// used here so that a provider's actual `CKA_KEY_TYPE` is not misclassified.
const CKK_SHA_1_HMAC: c_ulong = 0x0000_0028;
const CKK_SHA224_HMAC: c_ulong = 0x0000_002e;
const CKK_SHA256_HMAC: c_ulong = 0x0000_002b;
const CKK_SHA384_HMAC: c_ulong = 0x0000_002c;
const CKK_SHA512_HMAC: c_ulong = 0x0000_002d;
const CKK_GENERIC_SECRET: c_ulong = 0x0000_0010;

/// MAC algorithms executable through the published upstream binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MacAlgorithm {
    /// HMAC-SHA-1. Retained for compatibility; not recommended for new use.
    HmacSha1,
    /// HMAC-SHA-224.
    HmacSha224,
    /// HMAC-SHA-256.
    HmacSha256,
    /// HMAC-SHA-384.
    HmacSha384,
    /// HMAC-SHA-512.
    HmacSha512,
    /// AES-CMAC (RFC 4493), full 128-bit tag.
    AesCmac,
}

impl MacAlgorithm {
    /// Every algorithm executable through this module.
    pub const ALL: [Self; 6] = [
        Self::HmacSha1,
        Self::HmacSha224,
        Self::HmacSha256,
        Self::HmacSha384,
        Self::HmacSha512,
        Self::AesCmac,
    ];

    /// Exact full-tag length in bytes.
    pub fn output_length(self) -> usize {
        match self {
            Self::HmacSha1 => 20,
            Self::HmacSha224 => 28,
            Self::HmacSha256 => 32,
            Self::HmacSha384 => 48,
            Self::HmacSha512 => 64,
            Self::AesCmac => 16,
        }
    }

    /// Numeric PKCS#11 mechanism identifier.
    pub fn mechanism(self) -> MechanismType {
        match self {
            Self::HmacSha1 => MechanismType::SHA1_HMAC,
            Self::HmacSha224 => MechanismType::SHA224_HMAC,
            Self::HmacSha256 => MechanismType::SHA256_HMAC,
            Self::HmacSha384 => MechanismType::SHA384_HMAC,
            Self::HmacSha512 => MechanismType::SHA512_HMAC,
            Self::AesCmac => MechanismType::AES_CMAC,
        }
    }

    fn parameters(self) -> Mechanism<'static> {
        match self {
            Self::HmacSha1 => Mechanism::Sha1Hmac,
            Self::HmacSha224 => Mechanism::Sha224Hmac,
            Self::HmacSha256 => Mechanism::Sha256Hmac,
            Self::HmacSha384 => Mechanism::Sha384Hmac,
            Self::HmacSha512 => Mechanism::Sha512Hmac,
            Self::AesCmac => Mechanism::AesCMac,
        }
    }

    fn key_type(self) -> c_ulong {
        match self {
            Self::HmacSha1 => CKK_SHA_1_HMAC,
            Self::HmacSha224 => CKK_SHA224_HMAC,
            Self::HmacSha256 => CKK_SHA256_HMAC,
            Self::HmacSha384 => CKK_SHA384_HMAC,
            Self::HmacSha512 => CKK_SHA512_HMAC,
            Self::AesCmac => *KeyType::AES,
        }
    }

    /// Whether a numeric `CKA_KEY_TYPE` is valid for this MAC mechanism.
    ///
    /// Generic secret keys are accepted for HMAC, as permitted by the PKCS#11
    /// mechanism descriptions. AES-CMAC requires an AES key.
    pub(crate) fn matches_key_type(self, kind: c_ulong) -> bool {
        match self {
            Self::AesCmac => kind == *KeyType::AES,
            _ => kind == self.key_type() || kind == CKK_GENERIC_SECRET,
        }
    }
}

impl std::fmt::Display for MacAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::HmacSha1 => "hmac-sha1",
            Self::HmacSha224 => "hmac-sha224",
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
            Self::AesCmac => "aes-cmac",
        })
    }
}

/// Current key permissions for one MAC direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacCapabilities {
    /// Selected algorithm.
    pub algorithm: MacAlgorithm,
    /// `CKA_SIGN` is set.
    pub can_sign: bool,
    /// `CKA_VERIFY` is set.
    pub can_verify: bool,
}

fn key_type(object: &Object<'_, '_>) -> Result<c_ulong, Error> {
    match attribute(object, AttributeType::KeyType, true)? {
        Some(Attribute::KeyType(kind)) => Ok(*kind),
        _ => Err(Error::MissingMetadata("MAC key type")),
    }
}

fn secret_key(object: &Object<'_, '_>) -> Result<(), Error> {
    if !matches!(
        attribute(object, AttributeType::Class, true)?,
        Some(Attribute::Class(ObjectClass::SECRET_KEY))
    ) {
        return Err(Error::UnsupportedMac);
    }
    Ok(())
}

fn permitted(object: &Object<'_, '_>, algorithm: MacAlgorithm) -> Result<(), Error> {
    match attribute(object, AttributeType::AllowedMechanisms, false)? {
        Some(Attribute::AllowedMechanisms(allowed))
            if !allowed.is_empty() && !allowed.contains(&algorithm.mechanism()) =>
        {
            Err(Error::UnsupportedMac)
        }
        Some(Attribute::AllowedMechanisms(_)) | None => Ok(()),
        _ => Err(Error::MissingMetadata("CKA_ALLOWED_MECHANISMS")),
    }
}

fn mechanism_support(
    token: &Token<'_>,
    algorithm: MacAlgorithm,
    verify: bool,
) -> Result<bool, Error> {
    if !token.mechanisms()?.contains(&algorithm.mechanism()) {
        return Ok(false);
    }
    let info = token.mechanism_info(algorithm.mechanism())?;
    Ok(if verify { info.verify() } else { info.sign() })
}

fn capabilities(
    object: &Object<'_, '_>,
    algorithm: MacAlgorithm,
) -> Result<MacCapabilities, Error> {
    secret_key(object)?;
    let kind = key_type(object)?;
    let generic = kind == CKK_GENERIC_SECRET;
    let matches = match algorithm {
        MacAlgorithm::AesCmac => kind == *KeyType::AES,
        _ => kind == algorithm.key_type() || generic,
    };
    if !matches {
        return Err(Error::UnsupportedMac);
    }
    permitted(object, algorithm)?;
    let can_sign = match attribute(object, AttributeType::Sign, true)? {
        Some(Attribute::Sign(value)) => value,
        _ => return Err(Error::MissingMetadata("CKA_SIGN")),
    };
    let can_verify = match attribute(object, AttributeType::Verify, true)? {
        Some(Attribute::Verify(value)) => value,
        _ => return Err(Error::MissingMetadata("CKA_VERIFY")),
    };
    let token = object.session.token();
    if (can_sign && !mechanism_support(token, algorithm, false)?)
        || (can_verify && !mechanism_support(token, algorithm, true)?)
    {
        return Err(Error::UnsupportedMac);
    }
    Ok(MacCapabilities {
        algorithm,
        can_sign,
        can_verify,
    })
}

impl Token<'_> {
    /// Advertised MAC algorithms with a native sign or verify entry point.
    pub fn mac_options(&self) -> Result<Vec<MacAlgorithm>, Error> {
        let raw = self.module.raw()?;
        if !raw.is_fn_supported(Function::SignInit) || !raw.is_fn_supported(Function::Sign) {
            return Ok(Vec::new());
        }
        let mechanisms = self.mechanisms()?;
        let mut options = Vec::new();
        for algorithm in MacAlgorithm::ALL {
            let mechanism = algorithm.mechanism();
            if mechanisms.contains(&mechanism) {
                let info = self.mechanism_info(mechanism)?;
                if info.sign() || info.verify() {
                    options.push(algorithm);
                }
            }
        }
        Ok(options)
    }
}

impl Session<'_> {
    /// Inspect the selected secret key's MAC permissions without reading its value.
    pub fn mac_capabilities(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
    ) -> Result<MacCapabilities, Error> {
        capabilities(&self.resolve(key)?, algorithm)
    }

    fn prepare(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        verify: bool,
    ) -> Result<cryptoki::object::ObjectHandle, Error> {
        let object = self.resolve(key)?;
        let capabilities = capabilities(&object, algorithm)?;
        if (verify && !capabilities.can_verify) || (!verify && !capabilities.can_sign) {
            return Err(Error::UnsupportedMac);
        }
        Ok(object.handle)
    }

    /// Compute one MAC over a bounded buffer with a single native call.
    ///
    /// The exact full-tag length is checked. No software fallback or retry is
    /// performed.
    pub fn mac(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if input.len() > MAC_MAXIMUM_INPUT {
            return Err(Error::InvalidParameters("MAC input exceeds bound"));
        }
        let handle = self.prepare(key, algorithm, false)?;
        let output = self
            .operation("MAC", |raw| {
                raw.sign(&algorithm.parameters(), handle, input)
            })
            .map_err(|e| map_function_not_supported(e, Error::UnsupportedMac))?;
        if output.len() != algorithm.output_length() {
            return Err(Error::InvalidMac);
        }
        Ok(output)
    }

    /// Stream a MAC over chunks using a multipart native operation.
    pub fn mac_chunks<'a>(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<u8>, Error> {
        let handle = self.prepare(key, algorithm, false)?;
        let raw = self.token().module.raw()?;
        if !raw.is_fn_supported(Function::SignUpdate) || !raw.is_fn_supported(Function::SignFinal) {
            return Err(Error::UnsupportedMac);
        }
        let mechanism = algorithm.parameters();
        let output = self
            .operation("multipart MAC", |raw| {
                raw.sign_init(&mechanism, handle)?;
                for chunk in chunks {
                    raw.sign_update(chunk)?;
                }
                raw.sign_final()
            })
            .map_err(|e| map_function_not_supported(e, Error::UnsupportedMac))?;
        if output.len() != algorithm.output_length() {
            return Err(Error::InvalidMac);
        }
        Ok(output)
    }

    /// Verify a full-tag MAC on the token once.
    ///
    /// A mismatch terminates the native operation and leaves the session usable;
    /// other native failures invalidate it. No certificate or key association is
    /// implied.
    pub fn verify_mac(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        input: &[u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        if input.len() > MAC_MAXIMUM_INPUT {
            return Err(Error::InvalidParameters("MAC input exceeds bound"));
        }
        if tag.len() != algorithm.output_length() {
            return Err(Error::SignatureMismatch);
        }
        let handle = self.prepare(key, algorithm, true)?;
        self.validate()?;
        let raw = self.raw()?;
        self.healthy.set(false);
        match raw.verify(&algorithm.parameters(), handle, input, tag) {
            Ok(()) => {
                self.healthy.set(true);
                Ok(())
            }
            Err(NativeError::Pkcs11(
                RvError::SignatureInvalid | RvError::SignatureLenRange,
                Function::Verify,
            )) => {
                self.healthy.set(true);
                Err(Error::SignatureMismatch)
            }
            Err(error) => {
                if function_not_supported(&error) {
                    self.healthy.set(true);
                }
                Err(map_function_not_supported(
                    backend("verify MAC", error),
                    Error::UnsupportedMac,
                ))
            }
        }
    }

    /// Verify a MAC over chunks using a multipart native operation.
    pub fn verify_mac_chunks<'a>(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        chunks: impl IntoIterator<Item = &'a [u8]>,
        tag: &[u8],
    ) -> Result<(), Error> {
        if tag.len() != algorithm.output_length() {
            return Err(Error::SignatureMismatch);
        }
        let handle = self.prepare(key, algorithm, true)?;
        let module = self.token().module.raw()?;
        if !module.is_fn_supported(Function::VerifyUpdate)
            || !module.is_fn_supported(Function::VerifyFinal)
        {
            return Err(Error::UnsupportedMac);
        }
        let mechanism = algorithm.parameters();
        self.validate()?;
        let raw = self.raw()?;
        self.healthy.set(false);
        let result = (|| {
            raw.verify_init(&mechanism, handle)?;
            for chunk in chunks {
                raw.verify_update(chunk)?;
            }
            raw.verify_final(tag)
        })();
        match result {
            Ok(()) => {
                self.healthy.set(true);
                Ok(())
            }
            Err(NativeError::Pkcs11(
                RvError::SignatureInvalid | RvError::SignatureLenRange,
                Function::VerifyFinal,
            )) => {
                self.healthy.set(true);
                Err(Error::SignatureMismatch)
            }
            Err(error) => {
                if function_not_supported(&error) {
                    self.healthy.set(true);
                }
                Err(map_function_not_supported(
                    backend("multipart verify MAC", error),
                    Error::UnsupportedMac,
                ))
            }
        }
    }
}

/// Bounded request for a persistent MAC key.
///
/// HMAC keys are generic secret keys of the requested length. AES-CMAC keys are
/// AES keys with only signing/verification permission.
#[derive(Clone, Copy)]
pub struct MacKeyRequest<'a> {
    /// MAC algorithm the key will be used with.
    pub algorithm: MacAlgorithm,
    /// Key length in bytes. HMAC requires at least the PRF output length;
    /// AES-CMAC requires exactly 16, 24 or 32 bytes.
    pub length: usize,
    /// New nonempty CKA_ID, at most 128 bytes.
    pub id: &'a [u8],
    /// New nonempty CKA_LABEL, at most 128 bytes.
    pub label: &'a [u8],
}

impl std::fmt::Debug for MacKeyRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacKeyRequest")
            .field("algorithm", &self.algorithm)
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

impl MacKeyRequest<'_> {
    /// Validate identity and length bounds without provider access.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)?;
        match self.algorithm {
            MacAlgorithm::AesCmac => {
                if ![16, 24, 32].contains(&self.length) {
                    return Err(Error::InvalidParameters("AES-CMAC key length"));
                }
            }
            _ => {
                if self.length < self.algorithm.output_length() || self.length > 512 {
                    return Err(Error::InvalidParameters("HMAC key length"));
                }
            }
        }
        Ok(())
    }
}

impl Session<'_> {
    /// Generate one persistent MAC key in an RW session.
    ///
    /// HMAC uses `CKM_GENERIC_SECRET_KEY_GEN`; AES-CMAC uses `CKM_AES_KEY_GEN`
    /// with only sign/verify permission. Keys are private, sensitive and
    /// nonextractable. Duplicate IDs are checked before generation; no value is
    /// read, no retry occurs, and a provider failure may leave objects.
    pub fn generate_mac_key(
        &mut self,
        request: &MacKeyRequest<'_>,
    ) -> Result<Object<'_, '_>, Error> {
        request.validate()?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        if request.algorithm == MacAlgorithm::AesCmac {
            let size = match request.length {
                16 => AesKeySize::Bits128,
                24 => AesKeySize::Bits192,
                32 => AesKeySize::Bits256,
                _ => return Err(Error::InvalidParameters("AES-CMAC key length")),
            };
            return self.generate_aes_key(&AesKeyRequest {
                size,
                purpose: AesKeyPurpose::Authentication,
                id: request.id,
                label: request.label,
            });
        }
        if !self
            .find_objects(&[
                Attribute::Token(true),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::Id(request.id.to_vec()),
            ])?
            .is_empty()
        {
            return Err(Error::InvalidParameters("secret key ID already exists"));
        }
        let token = self.token();
        let mechanism = MechanismType::GENERIC_SECRET_KEY_GEN;
        if !token.mechanisms()?.contains(&mechanism) {
            return Err(Error::UnsupportedMac);
        }
        let info = token.mechanism_info(mechanism)?;
        if !info.generate()
            || !(info.min_key_size()..=info.max_key_size()).contains(&request.length)
        {
            return Err(Error::UnsupportedMac);
        }
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Verify(true),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Wrap(false),
            Attribute::Unwrap(false),
            Attribute::Derive(false),
            Attribute::Id(request.id.to_vec()),
            Attribute::Label(request.label.to_vec()),
            Attribute::ValueLen(
                request
                    .length
                    .try_into()
                    .map_err(|_| Error::InvalidParameters("HMAC key length"))?,
            ),
        ];
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
    fn key_types_preserve_the_oasis_values() {
        assert_eq!(CKK_SHA_1_HMAC, 40);
        assert_eq!(CKK_SHA224_HMAC, 46);
        assert_eq!(CKK_SHA256_HMAC, 43);
        assert_eq!(CKK_SHA384_HMAC, 44);
        assert_eq!(CKK_SHA512_HMAC, 45);
        assert_eq!(CKK_GENERIC_SECRET, 16);
        assert_eq!(MacAlgorithm::HmacSha384.key_type(), 44);
    }

    #[test]
    fn mac_key_requests_are_bounded_and_redacted() {
        let request = MacKeyRequest {
            algorithm: MacAlgorithm::HmacSha256,
            length: 32,
            id: b"id-canary",
            label: b"label-canary",
        };
        request.validate().unwrap();
        assert!(!format!("{request:?}").contains("canary"));
        for length in [31, 513] {
            assert!(MacKeyRequest { length, ..request }.validate().is_err());
        }
        for length in [16, 24, 32] {
            MacKeyRequest {
                algorithm: MacAlgorithm::AesCmac,
                length,
                ..request
            }
            .validate()
            .unwrap();
        }
        for length in [15, 20, 31, 33] {
            assert!(
                MacKeyRequest {
                    algorithm: MacAlgorithm::AesCmac,
                    length,
                    ..request
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn output_lengths_match_the_underlying_hash() {
        for (algorithm, length) in [
            (MacAlgorithm::HmacSha1, 20),
            (MacAlgorithm::HmacSha224, 28),
            (MacAlgorithm::HmacSha256, 32),
            (MacAlgorithm::HmacSha384, 48),
            (MacAlgorithm::HmacSha512, 64),
            (MacAlgorithm::AesCmac, 16),
        ] {
            assert_eq!(algorithm.output_length(), length);
        }
    }
}
