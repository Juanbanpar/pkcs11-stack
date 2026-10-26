// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeType, DigestAlgorithm, Error, KeyKind, MechanismType, ObjectClass,
    ObjectRef, Pin, PrivateKeyRef, PublicKeyRef, Session,
    error::backend,
    signing::{attribute, key_kind},
};
use cryptoki::mechanism::{
    Mechanism,
    rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource},
};
use cryptoki::{context::Function, session::UserType};
use secrecy::{ExposeSecret, SecretBox};

/// Direction of a token RSA-OAEP operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaCipherOperation {
    /// Encrypt using a public key with CKA_ENCRYPT.
    Encrypt,
    /// Decrypt using a private key with CKA_DECRYPT.
    Decrypt,
}
/// Current key size after class, permission and mechanism checks.
#[derive(Clone, Copy, Debug)]
pub struct RsaOaepCapabilities {
    /// Observed modulus size, restricted to 2048 through 16384 bits.
    pub modulus_bits: usize,
    /// Whether private decryption requires a separate context credential.
    pub always_authenticate: bool,
}
impl RsaOaepCapabilities {
    /// RSA ciphertext length in bytes.
    pub fn ciphertext_length(self) -> usize {
        self.modulus_bits.div_ceil(8)
    }
    /// Maximum plaintext for an empty label and matching SHA-2/MGF1 digests.
    pub fn maximum_plaintext(self, digest: DigestAlgorithm) -> usize {
        self.ciphertext_length()
            .saturating_sub(2 * digest.output_len() + 2)
    }
}
fn mechanism(digest: DigestAlgorithm) -> Mechanism<'static> {
    let (hash, mgf) = match digest {
        DigestAlgorithm::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
        DigestAlgorithm::Sha384 => (MechanismType::SHA384, PkcsMgfType::MGF1_SHA384),
        DigestAlgorithm::Sha512 => (MechanismType::SHA512, PkcsMgfType::MGF1_SHA512),
    };
    Mechanism::RsaPkcsOaep(PkcsOaepParams::new(hash, mgf, PkcsOaepSource::empty()))
}
fn capabilities(
    object: &crate::Object<'_, '_>,
    operation: RsaCipherOperation,
) -> Result<RsaOaepCapabilities, Error> {
    let (class, permission) = match operation {
        RsaCipherOperation::Encrypt => (ObjectClass::PUBLIC_KEY, AttributeType::Encrypt),
        RsaCipherOperation::Decrypt => (ObjectClass::PRIVATE_KEY, AttributeType::Decrypt),
    };
    if !matches!(attribute(object, AttributeType::Class, true)?, Some(Attribute::Class(value)) if value == class)
    {
        return Err(Error::UnsupportedCipher);
    }
    let enabled = match attribute(object, permission, true)? {
        Some(Attribute::Encrypt(value) | Attribute::Decrypt(value)) => value,
        _ => false,
    };
    if !enabled {
        return Err(Error::UnsupportedCipher);
    }
    let always_authenticate = if operation == RsaCipherOperation::Decrypt {
        match attribute(object, AttributeType::AlwaysAuthenticate, true)? {
            Some(Attribute::AlwaysAuthenticate(value)) => value,
            _ => return Err(Error::MissingMetadata("CKA_ALWAYS_AUTHENTICATE")),
        }
    } else {
        false
    };
    let KeyKind::Rsa { bits } = key_kind(object)? else {
        return Err(Error::UnsupportedCipher);
    };
    if !(2048..=16384).contains(&bits) {
        return Err(Error::UnsupportedCipher);
    }
    if let Some(Attribute::AllowedMechanisms(allowed)) =
        attribute(object, AttributeType::AllowedMechanisms, false)?
    {
        if !allowed.is_empty() && !allowed.contains(&MechanismType::RSA_PKCS_OAEP) {
            return Err(Error::UnsupportedCipher);
        }
    }
    let token = object.session.token();
    let functions = match operation {
        RsaCipherOperation::Encrypt => [Function::EncryptInit, Function::Encrypt],
        RsaCipherOperation::Decrypt => [Function::DecryptInit, Function::Decrypt],
    };
    let module = token.module.raw()?;
    if functions
        .into_iter()
        .any(|function| !module.is_fn_supported(function))
    {
        return Err(Error::UnsupportedCipher);
    }
    if !token.mechanisms()?.contains(&MechanismType::RSA_PKCS_OAEP) {
        return Err(Error::UnsupportedCipher);
    }
    let info = token.mechanism_info(MechanismType::RSA_PKCS_OAEP)?;
    if bits < info.min_key_size()
        || bits > info.max_key_size()
        || !(match operation {
            RsaCipherOperation::Encrypt => info.encrypt(),
            RsaCipherOperation::Decrypt => info.decrypt(),
        })
    {
        return Err(Error::UnsupportedCipher);
    }
    Ok(RsaOaepCapabilities {
        modulus_bits: bits,
        always_authenticate,
    })
}
impl Session<'_> {
    /// Inspect a uniquely resolved key without encryption or decryption.
    /// OAEP digest parameters are advisory: providers may reject advertised mechanisms.
    pub fn rsa_oaep_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: RsaCipherOperation,
    ) -> Result<RsaOaepCapabilities, Error> {
        capabilities(&self.resolve(key)?, operation)
    }
    /// Encrypt once, with matching SHA-2/MGF1 digest and empty label.
    /// No software fallback, padding downgrade or retry is performed.
    pub fn encrypt_rsa_oaep(
        &mut self,
        key: &PublicKeyRef,
        digest: DigestAlgorithm,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let object = self.resolve(key.as_object_ref())?;
        let caps = capabilities(&object, RsaCipherOperation::Encrypt)?;
        if plaintext.len() > caps.maximum_plaintext(digest) {
            return Err(Error::InvalidParameters("OAEP plaintext length"));
        }
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        let result = raw
            .encrypt(&mechanism(digest), object.handle, plaintext)
            .map_err(|e| backend("RSA OAEP encrypt", e))?;
        if result.len() != caps.ciphertext_length() {
            return Err(Error::InvalidCiphertext);
        }
        object.session.healthy.set(true);
        Ok(result)
    }
    /// Decrypt once without a context credential. Always-authenticate keys return
    /// ContextAuthenticationRequired before initialization. All plaintext buffers
    /// zeroize on error or drop; no plaintext is returned on failure.
    pub fn decrypt_rsa_oaep(
        &mut self,
        key: &PrivateKeyRef,
        digest: DigestAlgorithm,
        ciphertext: &[u8],
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        self.decrypt_rsa_oaep_with_context(key, digest, ciphertext, None)
    }
    /// Decrypt once with an optional per-operation credential, borrowed only for
    /// this call. Login occurs after initialization and before single-part
    /// completion. A context PIN for an ordinary key is rejected before crypto.
    pub fn decrypt_rsa_oaep_with_context(
        &mut self,
        key: &PrivateKeyRef,
        digest: DigestAlgorithm,
        ciphertext: &[u8],
        context_pin: Option<Pin<'_>>,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        let object = self.resolve(key.as_object_ref())?;
        let caps = capabilities(&object, RsaCipherOperation::Decrypt)?;
        if ciphertext.len() != caps.ciphertext_length() {
            return Err(Error::InvalidParameters("OAEP ciphertext length"));
        }
        let pin = if caps.always_authenticate {
            object
                .session
                .login_pin(context_pin.ok_or(Error::ContextAuthenticationRequired)?)?
        } else {
            if context_pin.is_some() {
                return Err(Error::InvalidParameters(
                    "context PIN for a key without always-authenticate",
                ));
            }
            None
        };
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        raw.decrypt_init(&mechanism(digest), object.handle)
            .map_err(|e| backend("RSA OAEP decrypt", e))?;
        if caps.always_authenticate {
            raw.login(UserType::ContextSpecific, pin)
                .map_err(|e| backend("context login", e))?;
        }
        let plaintext = raw
            .decrypt_initialized(ciphertext, caps.ciphertext_length())
            .map_err(|e| backend("RSA OAEP decrypt", e))?;
        if plaintext.expose_secret().len() > caps.maximum_plaintext(digest) {
            return Err(Error::InvalidCiphertext);
        }
        object.session.healthy.set(true);
        Ok(plaintext)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oaep_bounds_follow_modulus_and_digest_and_parameters_are_explicit() {
        let caps = RsaOaepCapabilities {
            modulus_bits: 2048,
            always_authenticate: false,
        };
        assert_eq!(caps.ciphertext_length(), 256);
        assert_eq!(caps.maximum_plaintext(DigestAlgorithm::Sha256), 190);
        assert_eq!(caps.maximum_plaintext(DigestAlgorithm::Sha384), 158);
        assert_eq!(caps.maximum_plaintext(DigestAlgorithm::Sha512), 126);
        assert_eq!(
            mechanism(DigestAlgorithm::Sha256).mechanism_type(),
            MechanismType::RSA_PKCS_OAEP
        );
    }
}
