// SPDX-License-Identifier: MIT OR Apache-2.0
//! One capability model shared by the runtime, client, CLI and desktop.
//!
//! The model reports what a token *advertises* and whether this project has a
//! typed execution path through the published `cryptoki` API. An advertised
//! mechanism is never treated as executable merely because it has a name.

use crate::{Error, MechanismInfo, MechanismType, Module, Token};
use cryptoki::context::Function;

/// Broad algorithm family used for grouping in application surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MechanismFamily {
    /// RSA key generation, signatures and encryption.
    Rsa,
    /// DSA key generation and signatures.
    Dsa,
    /// Prime-field elliptic curves (ECDSA, ECDH).
    Ec,
    /// Edwards curves (EdDSA).
    Edwards,
    /// Montgomery curves (X25519, X448).
    Montgomery,
    /// AES and other 128-bit block ciphers.
    Aes,
    /// DES/3DES and other legacy block ciphers.
    LegacyCipher,
    /// Standalone hash functions.
    Hash,
    /// Message authentication codes.
    Mac,
    /// Key derivation functions.
    Kdf,
    /// ML-KEM key encapsulation.
    MlKem,
    /// ML-DSA signatures.
    MlDsa,
    /// SLH-DSA signatures.
    SlhDsa,
    /// Mechanisms without a more specific classification.
    Other,
}

impl MechanismFamily {
    /// Stable lower-case identifier used by machine-readable output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Dsa => "dsa",
            Self::Ec => "ec",
            Self::Edwards => "edwards",
            Self::Montgomery => "montgomery",
            Self::Aes => "aes",
            Self::LegacyCipher => "legacy-cipher",
            Self::Hash => "hash",
            Self::Mac => "mac",
            Self::Kdf => "kdf",
            Self::MlKem => "ml-kem",
            Self::MlDsa => "ml-dsa",
            Self::SlhDsa => "slh-dsa",
            Self::Other => "other",
        }
    }
}

/// Operations a mechanism may support according to PKCS#11 mechanism flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MechanismOperation {
    /// Symmetric key generation.
    Generate,
    /// Asymmetric key-pair generation.
    GenerateKeyPair,
    /// Signing or MAC generation.
    Sign,
    /// Signature or MAC verification.
    Verify,
    /// Encryption.
    Encrypt,
    /// Decryption.
    Decrypt,
    /// Standalone digest.
    Digest,
    /// Key wrapping.
    Wrap,
    /// Key unwrapping.
    Unwrap,
    /// Key derivation.
    Derive,
    /// Key encapsulation.
    Encapsulate,
    /// Key decapsulation.
    Decapsulate,
    /// Message-based encryption.
    MessageEncrypt,
    /// Message-based decryption.
    MessageDecrypt,
}

impl MechanismOperation {
    /// Stable lower-case identifier used by machine-readable output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generate => "generate",
            Self::GenerateKeyPair => "generate-key-pair",
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::Digest => "digest",
            Self::Wrap => "wrap",
            Self::Unwrap => "unwrap",
            Self::Derive => "derive",
            Self::Encapsulate => "encapsulate",
            Self::Decapsulate => "decapsulate",
            Self::MessageEncrypt => "message-encrypt",
            Self::MessageDecrypt => "message-decrypt",
        }
    }
}

/// Advertised mechanism plus this project's execution classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MechanismCapability {
    /// Numeric PKCS#11 mechanism identifier.
    pub mechanism: MechanismType,
    /// Provider-facing name from the upstream identifier table.
    pub name: String,
    /// Broad algorithm family.
    pub family: MechanismFamily,
    /// Operations advertised by the provider.
    pub operations: Vec<MechanismOperation>,
    /// Advertised minimum key size in the mechanism's native unit.
    pub minimum_key_size: usize,
    /// Advertised maximum key size in the mechanism's native unit.
    pub maximum_key_size: usize,
    /// Provider reports hardware implementation.
    pub hardware: bool,
    /// A typed execution path exists through the published upstream API and runtime.
    pub executable: bool,
}

fn operation_list(info: MechanismInfo) -> Vec<MechanismOperation> {
    let mut operations = Vec::new();
    for (present, operation) in [
        (info.generate(), MechanismOperation::Generate),
        (
            info.generate_key_pair(),
            MechanismOperation::GenerateKeyPair,
        ),
        (info.sign(), MechanismOperation::Sign),
        (info.verify(), MechanismOperation::Verify),
        (info.encrypt(), MechanismOperation::Encrypt),
        (info.decrypt(), MechanismOperation::Decrypt),
        (info.digest(), MechanismOperation::Digest),
        (info.wrap(), MechanismOperation::Wrap),
        (info.unwrap(), MechanismOperation::Unwrap),
        (info.derive(), MechanismOperation::Derive),
        (info.encapsulate(), MechanismOperation::Encapsulate),
        (info.decapsulate(), MechanismOperation::Decapsulate),
        (info.message_encrypt(), MechanismOperation::MessageEncrypt),
        (info.message_decrypt(), MechanismOperation::MessageDecrypt),
    ] {
        if present {
            operations.push(operation);
        }
    }
    operations
}

/// Classify a mechanism identifier into a broad family.
///
/// The mapping is intentionally conservative: an unknown identifier is `Other`
/// rather than being guessed from its numeric range.
pub fn mechanism_family(mechanism: MechanismType) -> MechanismFamily {
    use MechanismType as M;
    match mechanism {
        M::RSA_PKCS_KEY_PAIR_GEN
        | M::RSA_PKCS
        | M::RSA_PKCS_PSS
        | M::RSA_PKCS_OAEP
        | M::RSA_X_509
        | M::SHA1_RSA_PKCS
        | M::SHA224_RSA_PKCS
        | M::SHA256_RSA_PKCS
        | M::SHA384_RSA_PKCS
        | M::SHA512_RSA_PKCS
        | M::SHA1_RSA_PKCS_PSS
        | M::SHA256_RSA_PKCS_PSS
        | M::SHA384_RSA_PKCS_PSS
        | M::SHA512_RSA_PKCS_PSS => MechanismFamily::Rsa,
        M::ECDSA
        | M::ECDSA_SHA1
        | M::ECDSA_SHA224
        | M::ECDSA_SHA256
        | M::ECDSA_SHA384
        | M::ECDSA_SHA512
        | M::ECDH1_DERIVE
        | M::ECC_KEY_PAIR_GEN => MechanismFamily::Ec,
        M::ECC_EDWARDS_KEY_PAIR_GEN | M::EDDSA => MechanismFamily::Edwards,
        M::ECC_MONTGOMERY_KEY_PAIR_GEN => MechanismFamily::Montgomery,
        M::AES_KEY_GEN
        | M::AES_ECB
        | M::AES_CBC
        | M::AES_CBC_PAD
        | M::AES_CTR
        | M::AES_GCM
        | M::AES_KEY_WRAP
        | M::AES_KEY_WRAP_PAD
        | M::AES_CBC_ENCRYPT_DATA => MechanismFamily::Aes,
        M::DES_KEY_GEN
        | M::DES2_KEY_GEN
        | M::DES3_KEY_GEN
        | M::DES_ECB
        | M::DES3_ECB
        | M::DES_CBC
        | M::DES3_CBC
        | M::DES_CBC_PAD
        | M::DES3_CBC_PAD => MechanismFamily::LegacyCipher,
        M::SHA1 | M::SHA224 | M::SHA256 | M::SHA384 | M::SHA512 => MechanismFamily::Hash,
        M::SHA1_HMAC
        | M::SHA224_HMAC
        | M::SHA256_HMAC
        | M::SHA384_HMAC
        | M::SHA512_HMAC
        | M::AES_CMAC
        | M::GENERIC_SECRET_KEY_GEN => MechanismFamily::Mac,
        M::HKDF_KEY_GEN
        | M::HKDF_DERIVE
        | M::HKDF_DATA
        | M::SP800_108_COUNTER_KDF
        | M::SP800_108_FEEDBACK_KDF
        | M::SP800_108_DOUBLE_PIPELINE_KDF
        | M::CONCATENATE_BASE_AND_KEY
        | M::CONCATENATE_BASE_AND_DATA
        | M::CONCATENATE_DATA_AND_BASE
        | M::XOR_BASE_AND_DATA
        | M::EXTRACT_KEY_FROM_KEY => MechanismFamily::Kdf,
        M::ML_KEM_KEY_PAIR_GEN | M::ML_KEM => MechanismFamily::MlKem,
        M::ML_DSA_KEY_PAIR_GEN
        | M::ML_DSA
        | M::HASH_ML_DSA
        | M::HASH_ML_DSA_SHA224
        | M::HASH_ML_DSA_SHA256
        | M::HASH_ML_DSA_SHA384
        | M::HASH_ML_DSA_SHA512
        | M::HASH_ML_DSA_SHA3_224
        | M::HASH_ML_DSA_SHA3_256
        | M::HASH_ML_DSA_SHA3_384
        | M::HASH_ML_DSA_SHA3_512
        | M::HASH_ML_DSA_SHAKE128
        | M::HASH_ML_DSA_SHAKE256 => MechanismFamily::MlDsa,
        M::SLH_DSA_KEY_PAIR_GEN
        | M::SLH_DSA
        | M::HASH_SLH_DSA
        | M::HASH_SLH_DSA_SHA224
        | M::HASH_SLH_DSA_SHA256
        | M::HASH_SLH_DSA_SHA384
        | M::HASH_SLH_DSA_SHA512
        | M::HASH_SLH_DSA_SHA3_224
        | M::HASH_SLH_DSA_SHA3_256
        | M::HASH_SLH_DSA_SHA3_384
        | M::HASH_SLH_DSA_SHA3_512
        | M::HASH_SLH_DSA_SHAKE128
        | M::HASH_SLH_DSA_SHAKE256 => MechanismFamily::SlhDsa,
        _ => MechanismFamily::Other,
    }
}

/// Whether this project has a typed execution path for a mechanism through the
/// published upstream API.
///
/// This is deliberately narrower than "the token advertises it": AES-CCM,
/// ChaCha20-Poly1305, PBKDF2, SHA-3, AES-KWP, general-length MACs and several
/// legacy families are not representable by published `cryptoki` 0.12.1.
pub fn is_runtime_supported(mechanism: MechanismType) -> bool {
    use MechanismType as M;
    matches!(
        mechanism,
        M::RSA_PKCS_KEY_PAIR_GEN
            | M::RSA_PKCS
            | M::RSA_PKCS_PSS
            | M::RSA_PKCS_OAEP
            | M::SHA224_RSA_PKCS
            | M::SHA256_RSA_PKCS
            | M::SHA384_RSA_PKCS
            | M::SHA512_RSA_PKCS
            | M::SHA256_RSA_PKCS_PSS
            | M::SHA384_RSA_PKCS_PSS
            | M::SHA512_RSA_PKCS_PSS
            | M::ECDSA
            | M::ECDSA_SHA224
            | M::ECDSA_SHA256
            | M::ECDSA_SHA384
            | M::ECDSA_SHA512
            | M::ECDH1_DERIVE
            | M::ECC_KEY_PAIR_GEN
            | M::AES_KEY_GEN
            | M::AES_ECB
            | M::AES_CBC
            | M::AES_CBC_PAD
            | M::AES_GCM
            | M::AES_CMAC
            | M::AES_KEY_WRAP
            | M::SHA1
            | M::SHA224
            | M::SHA256
            | M::SHA384
            | M::SHA512
            | M::SHA1_HMAC
            | M::SHA224_HMAC
            | M::SHA256_HMAC
            | M::SHA384_HMAC
            | M::SHA512_HMAC
            | M::GENERIC_SECRET_KEY_GEN
            | M::HKDF_DERIVE
            | M::SP800_108_COUNTER_KDF
            | M::SP800_108_FEEDBACK_KDF
            | M::SP800_108_DOUBLE_PIPELINE_KDF
            | M::CONCATENATE_BASE_AND_KEY
            | M::ML_KEM_KEY_PAIR_GEN
            | M::ML_KEM
            | M::ML_DSA_KEY_PAIR_GEN
            | M::ML_DSA
            | M::SLH_DSA_KEY_PAIR_GEN
            | M::SLH_DSA
    )
}

impl Token<'_> {
    /// Snapshot every advertised mechanism with its flags, bounds, family and
    /// whether a typed execution path exists.
    ///
    /// A provider may advertise a mechanism that this project cannot execute.
    /// That distinction is preserved in [`MechanismCapability::executable`].
    pub fn mechanism_capabilities(&self) -> Result<Vec<MechanismCapability>, Error> {
        let mut capabilities = Vec::new();
        for mechanism in self.mechanisms()? {
            let info = self.mechanism_info(mechanism)?;
            capabilities.push(MechanismCapability {
                mechanism,
                name: mechanism.to_string(),
                family: mechanism_family(mechanism),
                operations: operation_list(info),
                minimum_key_size: info.min_key_size(),
                maximum_key_size: info.max_key_size(),
                hardware: info.hardware(),
                executable: is_runtime_supported(mechanism),
            });
        }
        Ok(capabilities)
    }
}

/// A PKCS#11 function whose presence can be checked without invoking it.
#[derive(Clone, Copy, Debug)]
pub struct FunctionAvailability {
    /// Upstream function identifier.
    pub function: Function,
    /// Whether the loaded function list provides a non-null entry.
    pub supported: bool,
}

/// Functions relevant to the interfaces this project uses.
pub const INTERFACE_FUNCTIONS: &[Function] = &[
    Function::Initialize,
    Function::Finalize,
    Function::GetInfo,
    Function::GetSlotList,
    Function::GetTokenInfo,
    Function::GetMechanismList,
    Function::GetMechanismInfo,
    Function::OpenSession,
    Function::CloseSession,
    Function::GetSessionInfo,
    Function::Login,
    Function::Logout,
    Function::CreateObject,
    Function::DestroyObject,
    Function::GetAttributeValue,
    Function::SetAttributeValue,
    Function::FindObjectsInit,
    Function::FindObjects,
    Function::FindObjectsFinal,
    Function::EncryptInit,
    Function::Encrypt,
    Function::EncryptUpdate,
    Function::EncryptFinal,
    Function::DecryptInit,
    Function::Decrypt,
    Function::DecryptUpdate,
    Function::DecryptFinal,
    Function::DigestInit,
    Function::Digest,
    Function::DigestUpdate,
    Function::DigestFinal,
    Function::SignInit,
    Function::Sign,
    Function::SignUpdate,
    Function::SignFinal,
    Function::VerifyInit,
    Function::Verify,
    Function::VerifyUpdate,
    Function::VerifyFinal,
    Function::GenerateKey,
    Function::GenerateKeyPair,
    Function::WrapKey,
    Function::UnwrapKey,
    Function::DeriveKey,
    Function::GenerateRandom,
    Function::GetInterfaceList,
    Function::GetInterface,
    Function::LoginUser,
    Function::SessionCancel,
    Function::MessageEncryptInit,
    Function::EncryptMessage,
    Function::EncryptMessageBegin,
    Function::EncryptMessageNext,
    Function::MessageEncryptFinal,
    Function::MessageDecryptInit,
    Function::DecryptMessage,
    Function::DecryptMessageBegin,
    Function::DecryptMessageNext,
    Function::MessageDecryptFinal,
    Function::MessageSignInit,
    Function::SignMessage,
    Function::MessageSignFinal,
    Function::MessageVerifyInit,
    Function::VerifyMessage,
    Function::MessageVerifyFinal,
];

impl Module {
    /// Report which of the standard functions this module exposes.
    ///
    /// The upstream library selects a 3.2, 3.0 or legacy 2.40 function list.
    /// Availability is derived from the selected list; it is not assumed from
    /// the library's reported Cryptoki version.
    pub fn function_availability(&self) -> Result<Vec<FunctionAvailability>, Error> {
        let raw = self.raw()?;
        Ok(INTERFACE_FUNCTIONS
            .iter()
            .copied()
            .map(|function| FunctionAvailability {
                function,
                supported: raw.is_fn_supported(function),
            })
            .collect())
    }

    /// Check one standard function through the selected function list.
    pub fn supports_function(&self, function: Function) -> Result<bool, Error> {
        Ok(self.raw()?.is_fn_supported(function))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_cover_the_typed_upstream_mechanisms() {
        assert_eq!(
            mechanism_family(MechanismType::AES_GCM),
            MechanismFamily::Aes
        );
        assert_eq!(
            mechanism_family(MechanismType::ML_KEM),
            MechanismFamily::MlKem
        );
        assert_eq!(
            mechanism_family(MechanismType::SLH_DSA),
            MechanismFamily::SlhDsa
        );
        assert_eq!(
            mechanism_family(MechanismType::HKDF_DERIVE),
            MechanismFamily::Kdf
        );
        assert_eq!(
            mechanism_family(MechanismType::SHA256_HMAC),
            MechanismFamily::Mac
        );
        assert_eq!(
            mechanism_family(MechanismType::ECDH1_DERIVE),
            MechanismFamily::Ec
        );
        assert_eq!(
            mechanism_family(MechanismType::EDDSA),
            MechanismFamily::Edwards
        );
        assert_eq!(
            mechanism_family(MechanismType::ECC_MONTGOMERY_KEY_PAIR_GEN),
            MechanismFamily::Montgomery
        );
    }

    #[test]
    fn executable_classification_tracks_typed_upstream_variants() {
        for mechanism in [
            MechanismType::AES_CBC,
            MechanismType::SHA256,
            MechanismType::SHA256_HMAC,
            MechanismType::SP800_108_COUNTER_KDF,
            MechanismType::SLH_DSA,
            MechanismType::ML_DSA,
        ] {
            assert!(is_runtime_supported(mechanism), "{mechanism}");
        }
        // Typed upstream variants that this runtime has not exposed yet.
        assert!(!is_runtime_supported(MechanismType::HASH_SLH_DSA_SHA256));
        assert!(!is_runtime_supported(MechanismType::AES_CTR));
        assert!(!is_runtime_supported(MechanismType::EDDSA));
        // A vendor-defined identifier is representable but not executable here.
        let vendor = MechanismType::new_vendor_defined(
            cryptoki::mechanism::vendor_defined::CKM_VENDOR_DEFINED | 1,
        )
        .unwrap();
        assert!(!is_runtime_supported(vendor));
    }

    #[test]
    fn operation_identifiers_are_stable() {
        assert_eq!(
            MechanismOperation::GenerateKeyPair.as_str(),
            "generate-key-pair"
        );
        assert_eq!(MechanismFamily::MlKem.as_str(), "ml-kem");
    }
}
