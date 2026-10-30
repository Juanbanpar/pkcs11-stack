// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AesKeySize, Attribute, AttributeType, Error, MechanismType, ObjectClass, ObjectRef, Session,
    error::backend, signing::attribute,
};
use cryptoki::{
    context::Function,
    mechanism::{Mechanism, aead::GcmParams},
    object::KeyType,
};
use secrecy::{ExposeSecret, SecretBox};

/// Nonce length for this AES-GCM profile, in bytes.
pub const AES_GCM_NONCE_LENGTH: usize = 12;
/// Full authentication tag length, in bytes. The tag follows the ciphertext.
pub const AES_GCM_TAG_LENGTH: usize = 16;
/// Single-part plaintext allocation limit, in bytes (16 MiB).
pub const AES_GCM_MAXIMUM_PLAINTEXT: usize = 16 * 1024 * 1024;
/// Additional authenticated data limit, in bytes (1 MiB).
pub const AES_GCM_MAXIMUM_AAD: usize = 1024 * 1024;

/// Direction of an AES-GCM operation on a secret AES key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AesGcmOperation {
    /// Requires CKA_ENCRYPT and the requested single-part or multipart entry points.
    Encrypt,
    /// Requires CKA_DECRYPT and the requested single-part or multipart entry points.
    Decrypt,
}
/// Current key size after permission, mechanism, bounds and entry-point checks.
/// The nonce/tag profile is fixed; advertised support does not guarantee acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AesGcmCapabilities {
    /// AES-128, AES-192 or AES-256.
    pub key_size: AesKeySize,
}
/// Borrowed AES-GCM encryption input. Debug omits every buffer.
pub struct AesGcmEncryptRequest<'a> {
    /// Unique per key across all writers and restarts. This API neither generates
    /// nor tracks nonces; an error does not authorize reusing this nonce.
    pub nonce: &'a [u8; AES_GCM_NONCE_LENGTH],
    /// Authenticated but unencrypted data, at most 1 MiB; empty is permitted.
    pub aad: &'a [u8],
    /// At most 16 MiB; empty is permitted. No input copy is retained.
    pub plaintext: &'a [u8],
}
/// Borrowed AES-GCM decryption input. Debug omits every buffer.
pub struct AesGcmDecryptRequest<'a> {
    /// The encryption nonce; no normalization or nonce generation occurs.
    pub nonce: &'a [u8; AES_GCM_NONCE_LENGTH],
    /// The exact AAD used for encryption, at most 1 MiB; empty is permitted.
    pub aad: &'a [u8],
    /// Ciphertext followed by the full 16-byte tag, without a nonce or envelope.
    /// Length must be 16 through 16 MiB + 16 bytes.
    pub ciphertext: &'a [u8],
}
fn validate_lengths(aad: usize, input: usize, operation: AesGcmOperation) -> Result<(), Error> {
    let valid = aad <= AES_GCM_MAXIMUM_AAD
        && match operation {
            AesGcmOperation::Encrypt => input <= AES_GCM_MAXIMUM_PLAINTEXT,
            AesGcmOperation::Decrypt => (AES_GCM_TAG_LENGTH
                ..=AES_GCM_MAXIMUM_PLAINTEXT + AES_GCM_TAG_LENGTH)
                .contains(&input),
        };
    valid
        .then_some(())
        .ok_or(Error::InvalidParameters("AES GCM input length"))
}
impl AesGcmEncryptRequest<'_> {
    /// Check this profile's allocation bounds without I/O. Nonce uniqueness is
    /// the caller's responsibility and cannot be established by this check.
    pub fn validate(&self) -> Result<(), Error> {
        validate_lengths(
            self.aad.len(),
            self.plaintext.len(),
            AesGcmOperation::Encrypt,
        )
    }
}
impl AesGcmDecryptRequest<'_> {
    /// Check AAD and ciphertext/tag length bounds without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        validate_lengths(
            self.aad.len(),
            self.ciphertext.len(),
            AesGcmOperation::Decrypt,
        )
    }
}
impl std::fmt::Debug for AesGcmEncryptRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesGcmEncryptRequest([REDACTED])")
    }
}
impl std::fmt::Debug for AesGcmDecryptRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesGcmDecryptRequest([REDACTED])")
    }
}
pub(crate) fn capabilities(
    object: &crate::Object<'_, '_>,
    operation: AesGcmOperation,
    multipart: bool,
) -> Result<AesGcmCapabilities, Error> {
    if !matches!(
        attribute(object, AttributeType::Class, true)?,
        Some(Attribute::Class(ObjectClass::SECRET_KEY))
    ) || !matches!(
        attribute(object, AttributeType::KeyType, true)?,
        Some(Attribute::KeyType(KeyType::AES))
    ) {
        return Err(Error::UnsupportedAesGcm);
    }
    let (permission, functions): (_, &[Function]) = match (operation, multipart) {
        (AesGcmOperation::Encrypt, false) => (
            AttributeType::Encrypt,
            &[Function::EncryptInit, Function::Encrypt],
        ),
        (AesGcmOperation::Decrypt, false) => (
            AttributeType::Decrypt,
            &[Function::DecryptInit, Function::Decrypt],
        ),
        (AesGcmOperation::Encrypt, true) => (
            AttributeType::Encrypt,
            &[
                Function::EncryptInit,
                Function::EncryptUpdate,
                Function::EncryptFinal,
            ],
        ),
        (AesGcmOperation::Decrypt, true) => (
            AttributeType::Decrypt,
            &[
                Function::DecryptInit,
                Function::DecryptUpdate,
                Function::DecryptFinal,
            ],
        ),
    };
    if !matches!(
        attribute(object, permission, true)?,
        Some(Attribute::Encrypt(true) | Attribute::Decrypt(true))
    ) {
        return Err(Error::UnsupportedAesGcm);
    }
    let length = match attribute(object, AttributeType::ValueLen, true)? {
        Some(Attribute::ValueLen(length)) => usize::from(length),
        _ => return Err(Error::UnsupportedAesGcm),
    };
    let key_size = match length {
        16 => AesKeySize::Bits128,
        24 => AesKeySize::Bits192,
        32 => AesKeySize::Bits256,
        _ => return Err(Error::UnsupportedAesGcm),
    };
    if matches!(attribute(object, AttributeType::AllowedMechanisms, false)?,
        Some(Attribute::AllowedMechanisms(allowed)) if !allowed.is_empty() && !allowed.contains(&MechanismType::AES_GCM))
    {
        return Err(Error::UnsupportedAesGcm);
    }
    let token = object.session.token();
    let raw = token.module.raw()?;
    if functions
        .iter()
        .any(|function| !raw.is_fn_supported(*function))
        || !token.mechanisms()?.contains(&MechanismType::AES_GCM)
    {
        return Err(Error::UnsupportedAesGcm);
    }
    let info = token.mechanism_info(MechanismType::AES_GCM)?;
    if !(info.min_key_size()..=info.max_key_size()).contains(&length)
        || !match operation {
            AesGcmOperation::Encrypt => info.encrypt(),
            AesGcmOperation::Decrypt => info.decrypt(),
        }
    {
        return Err(Error::UnsupportedAesGcm);
    }
    Ok(AesGcmCapabilities { key_size })
}
impl Session<'_> {
    /// Inspect a uniquely resolved persistent AES key without performing crypto.
    /// Does not read key material or promise acceptance of the fixed nonce/tag profile.
    pub fn aes_gcm_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: AesGcmOperation,
    ) -> Result<AesGcmCapabilities, Error> {
        capabilities(&self.resolve(key)?, operation, false)
    }
    /// Encrypt once with CKM_AES_GCM, a 12-byte supplied nonce and 128-bit tag.
    /// Returns ciphertext || tag; nonce and AAD remain with the caller. The caller
    /// must ensure nonce uniqueness per key, including after errors. No retry,
    /// software fallback, output-size query or automatic nonce management occurs.
    /// Output storage is exactly plaintext length plus the 16-byte tag. Read-only
    /// sessions are permitted. Provider errors/unwinds or malformed outputs
    /// invalidate the session.
    pub fn encrypt_aes_gcm(
        &mut self,
        key: &ObjectRef,
        request: &AesGcmEncryptRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        request.validate()?;
        let object = self.resolve(key)?;
        capabilities(&object, AesGcmOperation::Encrypt, false)?;
        let mut nonce = *request.nonce;
        let params = GcmParams::new(&mut nonce, request.aad, 128.into())
            .map_err(|e| backend("AES GCM parameters", e))?;
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        raw.encrypt_init(&Mechanism::AesGcm(params), object.handle)
            .map_err(|e| backend("AES GCM encrypt init", e))?;
        let mut result = vec![0; request.plaintext.len() + AES_GCM_TAG_LENGTH];
        let written = raw
            .encrypt_initialized_into(request.plaintext, &mut result)
            .map_err(|e| backend("AES GCM encrypt", e))?;
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
    pub fn decrypt_aes_gcm(
        &mut self,
        key: &ObjectRef,
        request: &AesGcmDecryptRequest<'_>,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        request.validate()?;
        let object = self.resolve(key)?;
        capabilities(&object, AesGcmOperation::Decrypt, false)?;
        let mut nonce = *request.nonce;
        let params = GcmParams::new(&mut nonce, request.aad, 128.into())
            .map_err(|e| backend("AES GCM parameters", e))?;
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        raw.decrypt_init(&Mechanism::AesGcm(params), object.handle)
            .map_err(|e| backend("AES GCM decrypt", e))?;
        let plaintext = raw
            .decrypt_initialized(request.ciphertext, request.ciphertext.len())
            .map_err(|e| backend("AES GCM decrypt", e))?;
        if plaintext.expose_secret().len() != request.ciphertext.len() - AES_GCM_TAG_LENGTH
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
            (0, 0, AesGcmOperation::Encrypt, true),
            (
                AES_GCM_MAXIMUM_AAD,
                AES_GCM_MAXIMUM_PLAINTEXT,
                AesGcmOperation::Encrypt,
                true,
            ),
            (AES_GCM_MAXIMUM_AAD + 1, 0, AesGcmOperation::Encrypt, false),
            (
                0,
                AES_GCM_MAXIMUM_PLAINTEXT + 1,
                AesGcmOperation::Encrypt,
                false,
            ),
            (0, 15, AesGcmOperation::Decrypt, false),
            (0, 16, AesGcmOperation::Decrypt, true),
            (
                AES_GCM_MAXIMUM_AAD,
                AES_GCM_MAXIMUM_PLAINTEXT + 16,
                AesGcmOperation::Decrypt,
                true,
            ),
            (AES_GCM_MAXIMUM_AAD + 1, 16, AesGcmOperation::Decrypt, false),
            (
                0,
                AES_GCM_MAXIMUM_PLAINTEXT + 17,
                AesGcmOperation::Decrypt,
                false,
            ),
            (usize::MAX, usize::MAX, AesGcmOperation::Decrypt, false),
        ] {
            assert_eq!(validate_lengths(aad, input, op).is_ok(), valid);
        }
        let nonce = b"nonce-canary";
        let encrypt = AesGcmEncryptRequest {
            nonce,
            aad: b"aad-canary",
            plaintext: b"plaintext-canary",
        };
        let decrypt = AesGcmDecryptRequest {
            nonce,
            aad: b"aad-canary",
            ciphertext: b"ciphertext-canary",
        };
        assert!(encrypt.validate().is_ok());
        assert!(decrypt.validate().is_ok());
        assert!(!format!("{encrypt:?} {decrypt:?}").contains("canary"));
    }
}
