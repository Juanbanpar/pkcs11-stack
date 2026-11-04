// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod administration;
mod cancellation;
pub use cryptoki::session::CancelFlags;
mod aes_cmac;
pub use aes_cmac::{
    AES_CMAC_MAXIMUM_MESSAGE, AES_CMAC_TAG_LENGTH, AesCmacCapabilities, AesCmacOptions,
    AesCmacProfile, MacOperation,
};
mod aes_gcm;
mod aes_gcm_stream;
pub use aes_gcm::{
    AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_PLAINTEXT, AES_GCM_NONCE_LENGTH, AES_GCM_TAG_LENGTH,
    AesGcmCapabilities, AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmOperation,
};
pub use aes_gcm_stream::{AesGcmDecryption, AesGcmEncryption, AesGcmStreamParameters};
mod digest;
pub use digest::{DigestMode, DigestOperation, HashAlgorithm};
mod ecdh;
pub use ecdh::{EcdhKdf, EcdhKeyRequest, EcdhOutput};
mod eddsa;
mod montgomery;
mod montgomery_kdf;
pub use montgomery_kdf::{MontgomeryKdfRequest, MontgomeryOutput};
mod montgomery_named;
pub use montgomery_named::{MontgomeryNamedCurve, MontgomeryNamedPublicKey};
mod x448;
pub use x448::{X448Derivation, X448Kdf, X448KeyPairRequest, X448Output, X448PublicKey};
mod x25519;
pub use eddsa::{
    EdDsaCapabilities, EdDsaCurve, EdDsaNamedRequest, EdDsaNamedScheme, EdDsaPublicKey,
    EdDsaRequest,
};
pub use x25519::{X25519Derivation, X25519KeyPairRequest, X25519PublicKey};
mod encryption;
mod generation;
pub use generation::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, EcdhKeyPairRequest, RsaEncryptionKeyPairRequest,
};
mod hkdf;
mod kbkdf;
pub use kbkdf::{
    KbkdfCapabilities, KbkdfMode, KbkdfOptions, KbkdfOutput, KbkdfPrf, KbkdfPrfCapabilities,
    KbkdfPrfRequest, KbkdfRequest,
};
mod hmac;
mod mac;
pub use hmac::{
    HMAC_MAXIMUM_MESSAGE, HmacAlgorithm, HmacCapabilities, HmacKeyRequest, HmacOptions,
    HmacTagProfile,
};
pub use mac::{MacGeneration, MacVerification};
mod hash_ml_dsa;
mod hash_ml_dsa_stream;
pub use hash_ml_dsa_stream::{
    HashMlDsaParameters, HashMlDsaProfileParameters, HashMlDsaVerificationCapabilities,
    HashMlDsaVerificationOperation,
};
mod hybrid;
mod key_operations;
mod ml_dsa;
pub use hash_ml_dsa::{HashMlDsaCapabilities, HashMlDsaInput, HashMlDsaMode, HashMlDsaRequest};
mod ml_dsa_verify;
pub use ml_dsa_verify::{MlDsaVerificationCapabilities, MlDsaVerificationOperation};
mod ml_dsa_stream;
pub use ml_dsa_stream::{MlDsaParameters, MlDsaSigningOperation};
mod ml_kem;
pub use encryption::{RsaCipherOperation, RsaOaepCapabilities, RsaOaepParameters};
pub use hkdf::{HkdfCapabilities, HkdfMode, HkdfOutput, HkdfRequest};
pub use key_operations::{
    AesKeyWrapAlgorithm, AesKeyWrapCapabilities, EcdhDerivation, KeyOperation, KeyOperationProfile,
};
pub use ml_dsa::{
    MlDsaCapabilities, MlDsaHedging, MlDsaParameterSet, MlDsaPublicKey, MlDsaRequest,
    MlDsaSigningPolicy,
};
pub use ml_kem::{
    MlKemCapabilities, MlKemOperation, MlKemParameterSet, MlKemPublicKey, MlKemRequest,
};
mod error;
mod module;
mod pool;
mod session;
mod signing;
mod verification;
pub use pool::{SessionLease, SessionPool};
pub use signing::*;
mod signature_stream;
pub use signature_stream::{
    CLASSICAL_SIGNATURE_MAXIMUM_LENGTH, SignatureParameters, SigningOperation,
    VerificationOperation,
};
pub use verification::{VerificationCapabilities, VerifyRequest};

pub use cryptoki::context::{Function, InterfaceInfo, InterfaceSelection, InterfaceVersion};
pub use error::Error;
pub use module::{Module, ModuleOptions, Token, validate_token_uri};
pub use session::{AttributeValues, Authentication, Object, ObjectRef, Pin, Session, SessionMode};
// Reuse cryptoki's domain representations, without exposing lifecycle or handles.
pub use cryptoki::{
    context::Info as LibraryInfo,
    mechanism::{MechanismInfo, MechanismType},
    object::{Attribute, AttributeInfo, AttributeType, CertificateType, KeyType, ObjectClass},
    session::{
        SessionInfo, SessionState, TEMPLATE_METADATA_MAX_BYTES, TEMPLATE_METADATA_MAX_DEPTH,
        TEMPLATE_METADATA_MAX_MEMBERS, TemplateAttribute, TemplateMember, TemplateMetadata,
    },
    slot::{Slot, SlotInfo, TokenInfo},
};
