// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AesKeySize, Attribute, AttributeType, Error, MechanismType, ObjectClass, ObjectRef, Session,
    error::backend, signing::attribute,
};
use cryptoki::{
    context::Function,
    mechanism::{Mechanism, aead::CcmParams},
    object::KeyType,
};
use secrecy::{ExposeSecret, SecretBox};

/// Nonce length for this AES-CCM profile, in bytes.
pub const AES_CCM_NONCE_LENGTH: usize = 12;
/// Full authentication tag length, in bytes. The tag follows the ciphertext.
pub const AES_CCM_TAG_LENGTH: usize = 16;
/// Maximum plaintext length for a 12-byte CCM nonce (2^24 - 1 bytes).
pub const AES_CCM_MAXIMUM_PLAINTEXT: usize = 16 * 1024 * 1024 - 1;
/// Additional authenticated data limit, in bytes (1 MiB).
pub const AES_CCM_MAXIMUM_AAD: usize = 1024 * 1024;

/// Direction of an AES-CCM operation on a secret AES key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AesCcmOperation {
    /// Requires CKA_ENCRYPT and the requested API entry points.
    Encrypt,
    /// Requires CKA_DECRYPT and the requested API entry points.
    Decrypt,
}
/// Current key size after permission, mechanism, bounds and entry-point checks.
/// The nonce/tag profile is fixed; advertised support does not guarantee acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AesCcmCapabilities {
    /// AES-128, AES-192 or AES-256.
    pub key_size: AesKeySize,
}
/// Borrowed AES-CCM encryption input. Debug omits every buffer.
pub struct AesCcmEncryptRequest<'a> {
    /// Unique per key across all writers and restarts. This API neither generates
    /// nor tracks nonces; an error does not authorize reusing this nonce.
    pub nonce: &'a [u8; AES_CCM_NONCE_LENGTH],
    /// Authenticated but unencrypted data, at most 1 MiB; empty is permitted.
    pub aad: &'a [u8],
    /// At most 2^24 - 1 bytes; empty is permitted. The declared native data length excludes the MAC.
    pub plaintext: &'a [u8],
}
/// Borrowed AES-CCM decryption input. Debug omits every buffer.
pub struct AesCcmDecryptRequest<'a> {
    /// The encryption nonce; no normalization or nonce generation occurs.
    pub nonce: &'a [u8; AES_CCM_NONCE_LENGTH],
    /// The exact AAD used for encryption, at most 1 MiB; empty is permitted.
    pub aad: &'a [u8],
    /// Ciphertext followed by the full 16-byte tag, without a nonce or envelope.
    /// Length must be 16 through (2^24 - 1) + 16 bytes.
    pub ciphertext: &'a [u8],
}
fn validate_lengths(aad: usize, input: usize, operation: AesCcmOperation) -> Result<(), Error> {
    let valid = aad <= AES_CCM_MAXIMUM_AAD
        && match operation {
            AesCcmOperation::Encrypt => input <= AES_CCM_MAXIMUM_PLAINTEXT,
            AesCcmOperation::Decrypt => (AES_CCM_TAG_LENGTH
                ..=AES_CCM_MAXIMUM_PLAINTEXT + AES_CCM_TAG_LENGTH)
                .contains(&input),
        };
    valid
        .then_some(())
        .ok_or(Error::InvalidParameters("AES CCM input length"))
}
impl AesCcmEncryptRequest<'_> {
    /// Check this profile's allocation bounds without I/O. Nonce uniqueness is
    /// the caller's responsibility and cannot be established by this check.
    pub fn validate(&self) -> Result<(), Error> {
        validate_lengths(
            self.aad.len(),
            self.plaintext.len(),
            AesCcmOperation::Encrypt,
        )
    }
}
impl AesCcmDecryptRequest<'_> {
    /// Check AAD and ciphertext/tag length bounds without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        validate_lengths(
            self.aad.len(),
            self.ciphertext.len(),
            AesCcmOperation::Decrypt,
        )
    }
}
impl std::fmt::Debug for AesCcmEncryptRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesCcmEncryptRequest([REDACTED])")
    }
}
impl std::fmt::Debug for AesCcmDecryptRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesCcmDecryptRequest([REDACTED])")
    }
}
pub(crate) fn capabilities(
    object: &crate::Object<'_, '_>,
    operation: AesCcmOperation,
) -> Result<AesCcmCapabilities, Error> {
    if !matches!(
        attribute(object, AttributeType::Class, true)?,
        Some(Attribute::Class(ObjectClass::SECRET_KEY))
    ) || !matches!(
        attribute(object, AttributeType::KeyType, true)?,
        Some(Attribute::KeyType(KeyType::AES))
    ) {
        return Err(Error::UnsupportedAesCcm);
    }
    let (permission, functions): (_, &[Function]) = match operation {
        AesCcmOperation::Encrypt => (
            AttributeType::Encrypt,
            &[Function::EncryptInit, Function::Encrypt],
        ),
        AesCcmOperation::Decrypt => (
            AttributeType::Decrypt,
            &[Function::DecryptInit, Function::Decrypt],
        ),
    };
    if !matches!(
        attribute(object, permission, true)?,
        Some(Attribute::Encrypt(true) | Attribute::Decrypt(true))
    ) {
        return Err(Error::UnsupportedAesCcm);
    }
    let length = match attribute(object, AttributeType::ValueLen, true)? {
        Some(Attribute::ValueLen(length)) => usize::from(length),
        _ => return Err(Error::UnsupportedAesCcm),
    };
    let key_size = match length {
        16 => AesKeySize::Bits128,
        24 => AesKeySize::Bits192,
        32 => AesKeySize::Bits256,
        _ => return Err(Error::UnsupportedAesCcm),
    };
    if matches!(attribute(object, AttributeType::AllowedMechanisms, false)?,
        Some(Attribute::AllowedMechanisms(allowed)) if !allowed.is_empty() && !allowed.contains(&MechanismType::AES_CCM))
    {
        return Err(Error::UnsupportedAesCcm);
    }
    let token = object.session.token();
    let raw = token.module.raw()?;
    if functions
        .iter()
        .any(|function| !raw.is_fn_supported(*function))
        || !token.mechanisms()?.contains(&MechanismType::AES_CCM)
    {
        return Err(Error::UnsupportedAesCcm);
    }
    let info = token.mechanism_info(MechanismType::AES_CCM)?;
    if !(info.min_key_size()..=info.max_key_size()).contains(&length)
        || !match operation {
            AesCcmOperation::Encrypt => info.encrypt(),
            AesCcmOperation::Decrypt => info.decrypt(),
        }
    {
        return Err(Error::UnsupportedAesCcm);
    }
    Ok(AesCcmCapabilities { key_size })
}
impl Session<'_> {
    /// Inspect a uniquely resolved persistent AES key without performing crypto.
    /// Does not read key material or promise acceptance of the fixed nonce/tag profile.
    pub fn aes_ccm_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: AesCcmOperation,
    ) -> Result<AesCcmCapabilities, Error> {
        capabilities(&self.resolve(key)?, operation)
    }
    /// Encrypt once with CKM_AES_CCM, a supplied 12-byte nonce and 16-byte tag.
    /// Returns ciphertext || tag; nonce and AAD remain with the caller. The caller
    /// must ensure nonce uniqueness per key, including after errors. No retry,
    /// software fallback, output-size query or automatic nonce management occurs.
    /// Output storage is exactly plaintext length plus the 16-byte tag. Read-only
    /// sessions are permitted. Provider errors/unwinds or malformed outputs
    /// invalidate the session.
    pub fn encrypt_aes_ccm(
        &mut self,
        key: &ObjectRef,
        request: &AesCcmEncryptRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        request.validate()?;
        let object = self.resolve(key)?;
        capabilities(&object, AesCcmOperation::Encrypt)?;
        let mut nonce = *request.nonce;
        let params = CcmParams::new(
            request
                .plaintext
                .len()
                .try_into()
                .map_err(|_| Error::InvalidParameters("CCM data length"))?,
            &mut nonce,
            request.aad,
            16.into(),
        )
        .map_err(|e| backend("AES CCM parameters", e))?;
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        raw.encrypt_init(&Mechanism::AesCcm(params), object.handle)
            .map_err(|e| backend("AES CCM encrypt init", e))?;
        let mut result = vec![0; request.plaintext.len() + AES_CCM_TAG_LENGTH];
        let written = raw
            .encrypt_initialized_into(request.plaintext, &mut result)
            .map_err(|e| backend("AES CCM encrypt", e))?;
        if written != result.len() || nonce != *request.nonce {
            return Err(Error::InvalidKeyOutput);
        }
        object.session.healthy.set(true);
        Ok(result)
    }
    /// Decrypt and authenticate once, returning zeroizing, redacted plaintext only
    /// after provider success and exact-length checks. Tag/AAD/nonce failures
    /// return no plaintext and invalidate the session; native error context is retained.
    /// No multipart output, retry or fallback is exposed. Read-only sessions are
    /// permitted. Output storage is bounded and zeroizes on native failure or drop.
    pub fn decrypt_aes_ccm(
        &mut self,
        key: &ObjectRef,
        request: &AesCcmDecryptRequest<'_>,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        request.validate()?;
        let object = self.resolve(key)?;
        capabilities(&object, AesCcmOperation::Decrypt)?;
        let mut nonce = *request.nonce;
        let params = CcmParams::new(
            (request.ciphertext.len() - AES_CCM_TAG_LENGTH)
                .try_into()
                .map_err(|_| Error::InvalidParameters("CCM data length"))?,
            &mut nonce,
            request.aad,
            16.into(),
        )
        .map_err(|e| backend("AES CCM parameters", e))?;
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        raw.decrypt_init(&Mechanism::AesCcm(params), object.handle)
            .map_err(|e| backend("AES CCM decrypt", e))?;
        let plaintext = raw
            .decrypt_initialized_exact(
                request.ciphertext,
                request.ciphertext.len() - AES_CCM_TAG_LENGTH,
            )
            .map_err(|e| backend("AES CCM decrypt", e))?;
        if plaintext.expose_secret().len() != request.ciphertext.len() - AES_CCM_TAG_LENGTH
            || nonce != *request.nonce
        {
            return Err(Error::InvalidKeyOutput);
        }
        object.session.healthy.set(true);
        Ok(plaintext)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_and_requests_redact_all_buffers() {
        for (aad, input, op, valid) in [
            (0, 0, AesCcmOperation::Encrypt, true),
            (
                AES_CCM_MAXIMUM_AAD,
                AES_CCM_MAXIMUM_PLAINTEXT,
                AesCcmOperation::Encrypt,
                true,
            ),
            (AES_CCM_MAXIMUM_AAD + 1, 0, AesCcmOperation::Encrypt, false),
            (
                0,
                AES_CCM_MAXIMUM_PLAINTEXT + 1,
                AesCcmOperation::Encrypt,
                false,
            ),
            (0, 15, AesCcmOperation::Decrypt, false),
            (0, 16, AesCcmOperation::Decrypt, true),
            (
                AES_CCM_MAXIMUM_AAD,
                AES_CCM_MAXIMUM_PLAINTEXT + 16,
                AesCcmOperation::Decrypt,
                true,
            ),
            (AES_CCM_MAXIMUM_AAD + 1, 16, AesCcmOperation::Decrypt, false),
            (
                0,
                AES_CCM_MAXIMUM_PLAINTEXT + 17,
                AesCcmOperation::Decrypt,
                false,
            ),
            (usize::MAX, usize::MAX, AesCcmOperation::Decrypt, false),
        ] {
            assert_eq!(validate_lengths(aad, input, op).is_ok(), valid);
        }
        let nonce = b"nonce-canary";
        let encrypt = AesCcmEncryptRequest {
            nonce,
            aad: b"aad-canary",
            plaintext: b"plaintext-canary",
        };
        let decrypt = AesCcmDecryptRequest {
            nonce,
            aad: b"aad-canary",
            ciphertext: b"ciphertext-canary",
        };
        assert!(encrypt.validate().is_ok());
        assert!(decrypt.validate().is_ok());
        assert!(!format!("{encrypt:?} {decrypt:?}").contains("canary"));
    }
}
