// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeType, Error, MechanismType, ObjectClass, ObjectRef, Session,
    error::backend, signing::attribute,
};
use cryptoki::{
    context::Function,
    mechanism::{Mechanism, aead::ChaCha20Poly1305Params},
    object::KeyType,
};
use secrecy::{ExposeSecret, SecretBox};

/// Nonce length for this ChaCha20-Poly1305 profile, in bytes.
pub const CHACHA20_POLY1305_NONCE_LENGTH: usize = 12;
/// Full authentication tag length, in bytes. The tag follows the ciphertext.
pub const CHACHA20_POLY1305_TAG_LENGTH: usize = 16;
/// Application plaintext limit, in bytes (16 MiB), below the IETF counter limit.
pub const CHACHA20_POLY1305_MAXIMUM_PLAINTEXT: usize = 16 * 1024 * 1024;
/// Additional authenticated data limit, in bytes (1 MiB).
pub const CHACHA20_POLY1305_MAXIMUM_AAD: usize = 1024 * 1024;

/// Direction of a ChaCha20-Poly1305 operation on a secret ChaCha20 key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChaCha20Poly1305Operation {
    /// Requires CKA_ENCRYPT and the requested API entry points.
    Encrypt,
    /// Requires CKA_DECRYPT and the requested API entry points.
    Decrypt,
}
/// Current key size after permission, mechanism and entry-point checks.
/// The nonce/tag profile is fixed; advertised support does not guarantee acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChaCha20Poly1305Capabilities {
    /// Fixed 256-bit key length in bytes.
    pub key_length: usize,
}
/// Borrowed ChaCha20-Poly1305 encryption input. Debug omits every buffer.
pub struct ChaCha20Poly1305EncryptRequest<'a> {
    /// Unique per key across all writers and restarts. This API neither generates
    /// nor tracks nonces; an error does not authorize reusing this nonce.
    pub nonce: &'a [u8; CHACHA20_POLY1305_NONCE_LENGTH],
    /// Authenticated but unencrypted data, at most 1 MiB; empty is permitted.
    pub aad: &'a [u8],
    /// At most 16 MiB; empty is permitted.
    pub plaintext: &'a [u8],
}
/// Borrowed ChaCha20-Poly1305 decryption input. Debug omits every buffer.
pub struct ChaCha20Poly1305DecryptRequest<'a> {
    /// The encryption nonce; no normalization or nonce generation occurs.
    pub nonce: &'a [u8; CHACHA20_POLY1305_NONCE_LENGTH],
    /// The exact AAD used for encryption, at most 1 MiB; empty is permitted.
    pub aad: &'a [u8],
    /// Ciphertext followed by the full 16-byte tag, without a nonce or envelope.
    /// Length must be 16 through 16 MiB + 16 bytes.
    pub ciphertext: &'a [u8],
}
fn validate_lengths(
    aad: usize,
    input: usize,
    operation: ChaCha20Poly1305Operation,
) -> Result<(), Error> {
    let valid = aad <= CHACHA20_POLY1305_MAXIMUM_AAD
        && match operation {
            ChaCha20Poly1305Operation::Encrypt => input <= CHACHA20_POLY1305_MAXIMUM_PLAINTEXT,
            ChaCha20Poly1305Operation::Decrypt => (CHACHA20_POLY1305_TAG_LENGTH
                ..=CHACHA20_POLY1305_MAXIMUM_PLAINTEXT + CHACHA20_POLY1305_TAG_LENGTH)
                .contains(&input),
        };
    valid
        .then_some(())
        .ok_or(Error::InvalidParameters("ChaCha20-Poly1305 input length"))
}
impl ChaCha20Poly1305EncryptRequest<'_> {
    /// Check this profile's allocation bounds without I/O. Nonce uniqueness is
    /// the caller's responsibility and cannot be established by this check.
    pub fn validate(&self) -> Result<(), Error> {
        validate_lengths(
            self.aad.len(),
            self.plaintext.len(),
            ChaCha20Poly1305Operation::Encrypt,
        )
    }
}
impl ChaCha20Poly1305DecryptRequest<'_> {
    /// Check AAD and ciphertext/tag length bounds without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        validate_lengths(
            self.aad.len(),
            self.ciphertext.len(),
            ChaCha20Poly1305Operation::Decrypt,
        )
    }
}
impl std::fmt::Debug for ChaCha20Poly1305EncryptRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChaCha20Poly1305EncryptRequest([REDACTED])")
    }
}
impl std::fmt::Debug for ChaCha20Poly1305DecryptRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChaCha20Poly1305DecryptRequest([REDACTED])")
    }
}
pub(crate) fn capabilities(
    object: &crate::Object<'_, '_>,
    operation: ChaCha20Poly1305Operation,
) -> Result<ChaCha20Poly1305Capabilities, Error> {
    if !matches!(
        attribute(object, AttributeType::Class, true)?,
        Some(Attribute::Class(ObjectClass::SECRET_KEY))
    ) || !matches!(
        attribute(object, AttributeType::KeyType, true)?,
        Some(Attribute::KeyType(KeyType::CHACHA20))
    ) {
        return Err(Error::UnsupportedChaCha20Poly1305);
    }
    let (permission, functions): (_, &[Function]) = match operation {
        ChaCha20Poly1305Operation::Encrypt => (
            AttributeType::Encrypt,
            &[Function::EncryptInit, Function::Encrypt],
        ),
        ChaCha20Poly1305Operation::Decrypt => (
            AttributeType::Decrypt,
            &[Function::DecryptInit, Function::Decrypt],
        ),
    };
    if !matches!(
        attribute(object, permission, true)?,
        Some(Attribute::Encrypt(true) | Attribute::Decrypt(true))
    ) {
        return Err(Error::UnsupportedChaCha20Poly1305);
    }
    let length = match attribute(object, AttributeType::ValueLen, true)? {
        Some(Attribute::ValueLen(length)) => usize::from(length),
        _ => return Err(Error::UnsupportedChaCha20Poly1305),
    };
    if length != 32 {
        return Err(Error::UnsupportedChaCha20Poly1305);
    }
    if matches!(attribute(object, AttributeType::AllowedMechanisms, false)?,
        Some(Attribute::AllowedMechanisms(allowed)) if !allowed.is_empty() && !allowed.contains(&MechanismType::CHACHA20_POLY1305))
    {
        return Err(Error::UnsupportedChaCha20Poly1305);
    }
    let token = object.session.token();
    let raw = token.module.raw()?;
    if functions
        .iter()
        .any(|function| !raw.is_fn_supported(*function))
        || !token
            .mechanisms()?
            .contains(&MechanismType::CHACHA20_POLY1305)
    {
        return Err(Error::UnsupportedChaCha20Poly1305);
    }
    let info = token.mechanism_info(MechanismType::CHACHA20_POLY1305)?;
    // Section 6.61 does not define units for AEAD mechanism key-size bounds.
    // Validate the fixed key length via CKA_VALUE_LEN, without guessing units.
    if !match operation {
        ChaCha20Poly1305Operation::Encrypt => info.encrypt(),
        ChaCha20Poly1305Operation::Decrypt => info.decrypt(),
    } {
        return Err(Error::UnsupportedChaCha20Poly1305);
    }
    Ok(ChaCha20Poly1305Capabilities { key_length: length })
}
impl Session<'_> {
    /// Inspect a uniquely resolved persistent ChaCha20 key without performing crypto.
    /// Does not read key material or promise acceptance of the fixed nonce/tag profile.
    pub fn chacha20_poly1305_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: ChaCha20Poly1305Operation,
    ) -> Result<ChaCha20Poly1305Capabilities, Error> {
        capabilities(&self.resolve(key)?, operation)
    }
    /// Encrypt once with CKM_CHACHA20_POLY1305, a supplied 12-byte nonce and 16-byte tag.
    /// Returns ciphertext || tag; nonce and AAD remain with the caller. The caller
    /// must ensure nonce uniqueness per key, including after errors. No retry,
    /// software fallback, output-size query or automatic nonce management occurs.
    /// Output storage is exactly plaintext length plus the 16-byte tag. Read-only
    /// sessions are permitted. Provider errors/unwinds or malformed outputs
    /// invalidate the session.
    pub fn encrypt_chacha20_poly1305(
        &mut self,
        key: &ObjectRef,
        request: &ChaCha20Poly1305EncryptRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        request.validate()?;
        let object = self.resolve(key)?;
        capabilities(&object, ChaCha20Poly1305Operation::Encrypt)?;
        let mut nonce = *request.nonce;
        let params = ChaCha20Poly1305Params::new(&mut nonce, request.aad)
            .map_err(|e| backend("ChaCha20-Poly1305 parameters", e))?;
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        raw.encrypt_init(&Mechanism::ChaCha20Poly1305(params), object.handle)
            .map_err(|e| backend("ChaCha20-Poly1305 encrypt init", e))?;
        let mut result = vec![0; request.plaintext.len() + CHACHA20_POLY1305_TAG_LENGTH];
        let written = raw
            .encrypt_initialized_into(request.plaintext, &mut result)
            .map_err(|e| backend("ChaCha20-Poly1305 encrypt", e))?;
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
    pub fn decrypt_chacha20_poly1305(
        &mut self,
        key: &ObjectRef,
        request: &ChaCha20Poly1305DecryptRequest<'_>,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        request.validate()?;
        let object = self.resolve(key)?;
        capabilities(&object, ChaCha20Poly1305Operation::Decrypt)?;
        let mut nonce = *request.nonce;
        let params = ChaCha20Poly1305Params::new(&mut nonce, request.aad)
            .map_err(|e| backend("ChaCha20-Poly1305 parameters", e))?;
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        raw.decrypt_init(&Mechanism::ChaCha20Poly1305(params), object.handle)
            .map_err(|e| backend("ChaCha20-Poly1305 decrypt", e))?;
        let plaintext = raw
            .decrypt_initialized_exact(
                request.ciphertext,
                request.ciphertext.len() - CHACHA20_POLY1305_TAG_LENGTH,
            )
            .map_err(|e| backend("ChaCha20-Poly1305 decrypt", e))?;
        if plaintext.expose_secret().len()
            != request.ciphertext.len() - CHACHA20_POLY1305_TAG_LENGTH
            || nonce != *request.nonce
        {
            return Err(Error::InvalidKeyOutput);
        }
        object.session.healthy.set(true);
        Ok(plaintext)
    }
}

/// Generate one persistent, private, sensitive and nonextractable 256-bit key.
/// Only ChaCha20-Poly1305 encryption/decryption is allowed; identity is redacted.
#[derive(Clone, Copy)]
pub struct ChaCha20Poly1305KeyRequest<'a> {
    /// New nonempty secret ID, at most 128 bytes.
    pub id: &'a [u8],
    /// Nonempty label, at most 128 bytes.
    pub label: &'a [u8],
}
impl ChaCha20Poly1305KeyRequest<'_> {
    /// Validate identity bounds without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        crate::key_operations::validate_secret_identity(self.id, self.label)
    }
}
impl std::fmt::Debug for ChaCha20Poly1305KeyRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChaCha20Poly1305KeyRequest([REDACTED])")
    }
}
impl crate::Token<'_> {
    /// Advisory ChaCha20 key generation support. Bounds are in bytes (§6.58.4).
    /// Does not guarantee template acceptance or subsequent AEAD support.
    pub fn chacha20_poly1305_generation_supported(&self) -> Result<bool, Error> {
        if !self.module.raw()?.is_fn_supported(Function::GenerateKey)
            || !self
                .mechanisms()?
                .contains(&MechanismType::CHACHA20_KEY_GEN)
        {
            return Ok(false);
        }
        let info = self.mechanism_info(MechanismType::CHACHA20_KEY_GEN)?;
        Ok(info.generate() && (info.min_key_size()..=info.max_key_size()).contains(&32))
    }
}
impl Session<'_> {
    /// Generate an AEAD-only protected key in an RW session. Current generation
    /// support and duplicate secret IDs are checked before the native call.
    /// No retry or rollback occurs; failures can leave persistent objects and ID
    /// checks are not atomic with other writers. Check closure before publishing results.
    pub fn generate_chacha20_poly1305_key(
        &mut self,
        request: &ChaCha20Poly1305KeyRequest<'_>,
    ) -> Result<(), Error> {
        request.validate()?;
        self.validate()?;
        if self.mode != crate::SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        if !self.token().chacha20_poly1305_generation_supported()? {
            return Err(Error::UnsupportedChaCha20Poly1305);
        }
        let mut template = self.new_secret_template(request.id, request.label, true)?;
        for attribute in &mut template {
            if let Attribute::KeyType(kind) = attribute {
                *kind = KeyType::CHACHA20;
            }
        }
        template.push(Attribute::ValueLen(32.into()));
        template.push(Attribute::AllowedMechanisms(vec![
            MechanismType::CHACHA20_POLY1305,
        ]));
        self.write_operation("generate ChaCha20-Poly1305 key", |raw| {
            raw.generate_key(&Mechanism::ChaCha20KeyGen, &template)
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_and_requests_redact_all_buffers() {
        for (aad, input, op, valid) in [
            (0, 0, ChaCha20Poly1305Operation::Encrypt, true),
            (
                CHACHA20_POLY1305_MAXIMUM_AAD,
                CHACHA20_POLY1305_MAXIMUM_PLAINTEXT,
                ChaCha20Poly1305Operation::Encrypt,
                true,
            ),
            (
                CHACHA20_POLY1305_MAXIMUM_AAD + 1,
                0,
                ChaCha20Poly1305Operation::Encrypt,
                false,
            ),
            (
                0,
                CHACHA20_POLY1305_MAXIMUM_PLAINTEXT + 1,
                ChaCha20Poly1305Operation::Encrypt,
                false,
            ),
            (0, 15, ChaCha20Poly1305Operation::Decrypt, false),
            (0, 16, ChaCha20Poly1305Operation::Decrypt, true),
            (
                CHACHA20_POLY1305_MAXIMUM_AAD,
                CHACHA20_POLY1305_MAXIMUM_PLAINTEXT + 16,
                ChaCha20Poly1305Operation::Decrypt,
                true,
            ),
            (
                CHACHA20_POLY1305_MAXIMUM_AAD + 1,
                16,
                ChaCha20Poly1305Operation::Decrypt,
                false,
            ),
            (
                0,
                CHACHA20_POLY1305_MAXIMUM_PLAINTEXT + 17,
                ChaCha20Poly1305Operation::Decrypt,
                false,
            ),
            (
                usize::MAX,
                usize::MAX,
                ChaCha20Poly1305Operation::Decrypt,
                false,
            ),
        ] {
            assert_eq!(validate_lengths(aad, input, op).is_ok(), valid);
        }
        let nonce = b"nonce-canary";
        let encrypt = ChaCha20Poly1305EncryptRequest {
            nonce,
            aad: b"aad-canary",
            plaintext: b"plaintext-canary",
        };
        let decrypt = ChaCha20Poly1305DecryptRequest {
            nonce,
            aad: b"aad-canary",
            ciphertext: b"ciphertext-canary",
        };
        assert!(encrypt.validate().is_ok());
        assert!(decrypt.validate().is_ok());
        assert!(!format!("{encrypt:?} {decrypt:?}").contains("canary"));
    }
}
