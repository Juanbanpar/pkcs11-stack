// SPDX-License-Identifier: MIT OR Apache-2.0
//! Token AES block-cipher operations for the modes with typed upstream
//! mechanisms: ECB, CBC and CBC with PKCS#7 padding.
//!
//! AES-CTR, AES-XTS, AES-CCM and ChaCha20-Poly1305 have no typed mechanism in
//! published `cryptoki` 0.12.1 and are therefore not executable here.

use crate::{
    AesKeySize, Attribute, AttributeType, Error, MechanismType, Object, ObjectClass, ObjectRef,
    Session, Token, error::map_function_not_supported, signing::attribute,
};
use cryptoki::{context::Function, mechanism::Mechanism, object::KeyType};
use secrecy::{ExposeSecret, SecretBox};

/// Maximum single-part symmetric input, in bytes (16 MiB).
pub const AES_MAXIMUM_INPUT: usize = 16 * 1024 * 1024;

/// AES block size in bytes.
pub const AES_BLOCK_SIZE: usize = 16;

/// AES modes executable through the published upstream binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AesMode {
    /// ECB. Input must be a multiple of the block size; no IV.
    Ecb,
    /// CBC. Input must be a multiple of the block size; 16-byte IV.
    Cbc,
    /// CBC with PKCS#7 padding. Any input length; 16-byte IV.
    CbcPad,
}

impl AesMode {
    /// Every mode executable through this module.
    pub const ALL: [Self; 3] = [Self::Ecb, Self::Cbc, Self::CbcPad];

    /// Whether this mode requires an explicit 16-byte IV.
    pub fn requires_iv(self) -> bool {
        !matches!(self, Self::Ecb)
    }

    /// Numeric PKCS#11 mechanism identifier.
    pub fn mechanism(self) -> MechanismType {
        match self {
            Self::Ecb => MechanismType::AES_ECB,
            Self::Cbc => MechanismType::AES_CBC,
            Self::CbcPad => MechanismType::AES_CBC_PAD,
        }
    }

    fn parameters(self, iv: Option<[u8; AES_BLOCK_SIZE]>) -> Result<Mechanism<'static>, Error> {
        match (self, iv) {
            (Self::Ecb, None) => Ok(Mechanism::AesEcb),
            (Self::Cbc, Some(iv)) => Ok(Mechanism::AesCbc(iv)),
            (Self::CbcPad, Some(iv)) => Ok(Mechanism::AesCbcPad(iv)),
            (Self::Ecb, Some(_)) => Err(Error::InvalidParameters("ECB takes no IV")),
            (Self::Cbc | Self::CbcPad, None) => {
                Err(Error::InvalidParameters("CBC requires a 16-byte IV"))
            }
        }
    }
}

impl std::fmt::Display for AesMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ecb => "aes-ecb",
            Self::Cbc => "aes-cbc",
            Self::CbcPad => "aes-cbc-pad",
        })
    }
}

/// Direction of an AES block-cipher operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AesDirection {
    /// Requires `CKA_ENCRYPT`.
    Encrypt,
    /// Requires `CKA_DECRYPT`.
    Decrypt,
}

/// Current key size and mode after permission and mechanism checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AesCipherCapabilities {
    /// AES-128, AES-192 or AES-256.
    pub key_size: AesKeySize,
    /// Selected mode.
    pub mode: AesMode,
}

/// Borrowed AES encryption input. Debug omits every buffer.
pub struct AesEncryptRequest<'a> {
    /// Block-cipher mode.
    pub mode: AesMode,
    /// Exactly 16 bytes for CBC/CBC-PAD; absent for ECB.
    pub iv: Option<&'a [u8; AES_BLOCK_SIZE]>,
    /// At most 16 MiB. ECB/CBC require a multiple of the block size.
    pub plaintext: &'a [u8],
}

/// Borrowed AES decryption input. Debug omits every buffer.
pub struct AesDecryptRequest<'a> {
    /// Block-cipher mode.
    pub mode: AesMode,
    /// Exactly 16 bytes for CBC/CBC-PAD; absent for ECB.
    pub iv: Option<&'a [u8; AES_BLOCK_SIZE]>,
    /// At most 16 MiB. ECB/CBC require a multiple of the block size.
    pub ciphertext: &'a [u8],
}

impl std::fmt::Debug for AesEncryptRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesEncryptRequest([REDACTED])")
    }
}

impl std::fmt::Debug for AesDecryptRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesDecryptRequest([REDACTED])")
    }
}

fn validate_length(mode: AesMode, length: usize) -> Result<(), Error> {
    if length > AES_MAXIMUM_INPUT {
        return Err(Error::InvalidParameters("AES input exceeds bound"));
    }
    if !matches!(mode, AesMode::CbcPad) && length % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidParameters("AES input is not block aligned"));
    }
    Ok(())
}

impl AesEncryptRequest<'_> {
    /// Validate bounds and IV shape without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        validate_length(self.mode, self.plaintext.len())?;
        if self.mode.requires_iv() != self.iv.is_some() {
            return Err(Error::InvalidParameters("AES IV shape"));
        }
        Ok(())
    }
}

impl AesDecryptRequest<'_> {
    /// Validate bounds and IV shape without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        validate_length(self.mode, self.ciphertext.len())?;
        if self.mode.requires_iv() != self.iv.is_some() {
            return Err(Error::InvalidParameters("AES IV shape"));
        }
        Ok(())
    }
}

fn key_size(object: &Object<'_, '_>) -> Result<AesKeySize, Error> {
    if !matches!(
        attribute(object, AttributeType::Class, true)?,
        Some(Attribute::Class(ObjectClass::SECRET_KEY))
    ) || !matches!(
        attribute(object, AttributeType::KeyType, true)?,
        Some(Attribute::KeyType(KeyType::AES))
    ) {
        return Err(Error::UnsupportedCipherMode);
    }
    match attribute(object, AttributeType::ValueLen, true)? {
        Some(Attribute::ValueLen(length)) => match usize::from(length) {
            16 => Ok(AesKeySize::Bits128),
            24 => Ok(AesKeySize::Bits192),
            32 => Ok(AesKeySize::Bits256),
            _ => Err(Error::UnsupportedCipherMode),
        },
        _ => Err(Error::UnsupportedCipherMode),
    }
}

fn capabilities(
    object: &Object<'_, '_>,
    mode: AesMode,
    direction: AesDirection,
) -> Result<AesCipherCapabilities, Error> {
    let key_size = key_size(object)?;
    let (permission, flag) = match direction {
        AesDirection::Encrypt => (AttributeType::Encrypt, true),
        AesDirection::Decrypt => (AttributeType::Decrypt, false),
    };
    let enabled = match attribute(object, permission, true)? {
        Some(Attribute::Encrypt(value) | Attribute::Decrypt(value)) => value,
        _ => false,
    };
    if !enabled {
        return Err(Error::UnsupportedCipherMode);
    }
    if let Some(Attribute::AllowedMechanisms(allowed)) =
        attribute(object, AttributeType::AllowedMechanisms, false)?
    {
        if !allowed.is_empty() && !allowed.contains(&mode.mechanism()) {
            return Err(Error::UnsupportedCipherMode);
        }
    }
    let token = object.session.token();
    let raw = token.module.raw()?;
    let functions = match direction {
        AesDirection::Encrypt => [Function::EncryptInit, Function::Encrypt],
        AesDirection::Decrypt => [Function::DecryptInit, Function::Decrypt],
    };
    if functions
        .into_iter()
        .any(|function| !raw.is_fn_supported(function))
        || !token.mechanisms()?.contains(&mode.mechanism())
    {
        return Err(Error::UnsupportedCipherMode);
    }
    let info = token.mechanism_info(mode.mechanism())?;
    let size = key_size.length();
    if !(info.min_key_size()..=info.max_key_size()).contains(&size)
        || (flag && !info.encrypt())
        || (!flag && !info.decrypt())
    {
        return Err(Error::UnsupportedCipherMode);
    }
    Ok(AesCipherCapabilities { key_size, mode })
}

impl Token<'_> {
    /// Advertised AES modes with a native encryption or decryption entry point.
    pub fn aes_mode_options(&self) -> Result<Vec<AesMode>, Error> {
        let mechanisms = self.mechanisms()?;
        Ok(AesMode::ALL
            .into_iter()
            .filter(|mode| mechanisms.contains(&mode.mechanism()))
            .collect())
    }
}

impl Session<'_> {
    /// Inspect a uniquely resolved AES key without performing crypto.
    pub fn aes_cipher_capabilities(
        &mut self,
        key: &ObjectRef,
        mode: AesMode,
        direction: AesDirection,
    ) -> Result<AesCipherCapabilities, Error> {
        capabilities(&self.resolve(key)?, mode, direction)
    }

    /// Encrypt one bounded buffer with a single native call.
    pub fn encrypt_aes(
        &mut self,
        key: &ObjectRef,
        request: &AesEncryptRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        request.validate()?;
        let object = self.resolve(key)?;
        capabilities(&object, request.mode, AesDirection::Encrypt)?;
        let iv = request.iv.copied();
        let mechanism = request.mode.parameters(iv)?;
        let output = object
            .session
            .operation("AES encrypt", |raw| {
                raw.encrypt(&mechanism, object.handle, request.plaintext)
            })
            .map_err(|e| map_function_not_supported(e, Error::UnsupportedCipherMode))?;
        let maximum = match request.mode {
            AesMode::CbcPad => request.plaintext.len() + AES_BLOCK_SIZE,
            AesMode::Ecb | AesMode::Cbc => request.plaintext.len(),
        };
        if output.len() > maximum || output.len() % AES_BLOCK_SIZE != 0 {
            return Err(Error::InvalidCipherOutput);
        }
        Ok(output)
    }

    /// Decrypt one bounded buffer, returning zeroizing plaintext only after
    /// successful completion and length checks.
    pub fn decrypt_aes(
        &mut self,
        key: &ObjectRef,
        request: &AesDecryptRequest<'_>,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        request.validate()?;
        let object = self.resolve(key)?;
        capabilities(&object, request.mode, AesDirection::Decrypt)?;
        let iv = request.iv.copied();
        let mechanism = request.mode.parameters(iv)?;
        let plaintext = SecretBox::new(Box::new(
            object
                .session
                .operation("AES decrypt", |raw| {
                    raw.decrypt(&mechanism, object.handle, request.ciphertext)
                })
                .map_err(|e| map_function_not_supported(e, Error::UnsupportedCipherMode))?,
        ));
        if plaintext.expose_secret().len() > request.ciphertext.len() {
            return Err(Error::InvalidCipherOutput);
        }
        Ok(plaintext)
    }

    /// Stream encryption through a multipart native operation.
    pub fn encrypt_aes_chunks<'a>(
        &mut self,
        key: &ObjectRef,
        mode: AesMode,
        iv: Option<&[u8; AES_BLOCK_SIZE]>,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<u8>, Error> {
        let object = self.resolve(key)?;
        capabilities(&object, mode, AesDirection::Encrypt)?;
        let mechanism = mode.parameters(iv.copied())?;
        let module = object.session.token().module.raw()?;
        if !module.is_fn_supported(Function::EncryptUpdate)
            || !module.is_fn_supported(Function::EncryptFinal)
        {
            return Err(Error::UnsupportedCipherMode);
        }
        object
            .session
            .operation("multipart AES encrypt", |raw| {
                raw.encrypt_init(&mechanism, object.handle)?;
                let mut output = Vec::new();
                for chunk in chunks {
                    output.extend_from_slice(&raw.encrypt_update(chunk)?);
                    if output.len() > AES_MAXIMUM_INPUT + AES_BLOCK_SIZE {
                        return Err(cryptoki::error::Error::InvalidValue);
                    }
                }
                output.extend_from_slice(&raw.encrypt_final()?);
                if output.len() > AES_MAXIMUM_INPUT + AES_BLOCK_SIZE {
                    return Err(cryptoki::error::Error::InvalidValue);
                }
                Ok(output)
            })
            .map_err(|e| map_function_not_supported(e, Error::UnsupportedCipherMode))
    }

    /// Stream decryption through a multipart native operation.
    pub fn decrypt_aes_chunks<'a>(
        &mut self,
        key: &ObjectRef,
        mode: AesMode,
        iv: Option<&[u8; AES_BLOCK_SIZE]>,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        let object = self.resolve(key)?;
        capabilities(&object, mode, AesDirection::Decrypt)?;
        let mechanism = mode.parameters(iv.copied())?;
        let module = object.session.token().module.raw()?;
        if !module.is_fn_supported(Function::DecryptUpdate)
            || !module.is_fn_supported(Function::DecryptFinal)
        {
            return Err(Error::UnsupportedCipherMode);
        }
        let plaintext = object
            .session
            .operation("multipart AES decrypt", |raw| {
                raw.decrypt_init(&mechanism, object.handle)?;
                let mut output = Vec::new();
                for chunk in chunks {
                    output.extend_from_slice(&raw.decrypt_update(chunk)?);
                    if output.len() > AES_MAXIMUM_INPUT {
                        return Err(cryptoki::error::Error::InvalidValue);
                    }
                }
                output.extend_from_slice(&raw.decrypt_final()?);
                if output.len() > AES_MAXIMUM_INPUT {
                    return Err(cryptoki::error::Error::InvalidValue);
                }
                Ok(output)
            })
            .map_err(|e| map_function_not_supported(e, Error::UnsupportedCipherMode))?;
        Ok(SecretBox::new(Box::new(plaintext)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iv_and_alignment_rules_are_explicit() {
        let iv = [0u8; 16];
        let block = [0u8; 16];
        assert!(
            AesEncryptRequest {
                mode: AesMode::Cbc,
                iv: Some(&iv),
                plaintext: &block,
            }
            .validate()
            .is_ok()
        );
        assert!(
            AesEncryptRequest {
                mode: AesMode::Cbc,
                iv: Some(&iv),
                plaintext: &[0u8; 15],
            }
            .validate()
            .is_err()
        );
        assert!(
            AesEncryptRequest {
                mode: AesMode::CbcPad,
                iv: Some(&iv),
                plaintext: &[0u8; 15],
            }
            .validate()
            .is_ok()
        );
        assert!(
            AesEncryptRequest {
                mode: AesMode::Ecb,
                iv: Some(&iv),
                plaintext: &block,
            }
            .validate()
            .is_err()
        );
        assert!(
            AesEncryptRequest {
                mode: AesMode::Cbc,
                iv: None,
                plaintext: &block,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn modes_map_to_typed_mechanisms() {
        assert_eq!(AesMode::Ecb.mechanism(), MechanismType::AES_ECB);
        assert_eq!(AesMode::Cbc.mechanism(), MechanismType::AES_CBC);
        assert_eq!(AesMode::CbcPad.mechanism(), MechanismType::AES_CBC_PAD);
        assert!(AesMode::Cbc.requires_iv());
        assert!(!AesMode::Ecb.requires_iv());
    }
}
