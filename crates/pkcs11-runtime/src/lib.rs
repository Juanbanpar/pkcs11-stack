// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod administration;
mod aes_gcm;
pub use aes_gcm::{
    AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_PLAINTEXT, AES_GCM_NONCE_LENGTH, AES_GCM_TAG_LENGTH,
    AesGcmCapabilities, AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmOperation,
};
mod capability;
pub use capability::{
    FunctionAvailability, INTERFACE_FUNCTIONS, MechanismCapability, MechanismFamily,
    MechanismOperation, is_runtime_supported, mechanism_family,
};
mod digest;
mod eddsa;
mod montgomery;
pub use eddsa::{EdDsaCapabilities, EdDsaCurve, EdDsaPublicKey, EdDsaRequest};
pub use montgomery::{
    MontgomeryCapabilities, MontgomeryCurve, MontgomeryDerivation, MontgomeryKdf, MontgomeryOutput,
    MontgomeryPublicKey,
};
mod encryption;
pub use digest::{DIGEST_MAXIMUM_INPUT, HashAlgorithm};
mod mac;
pub use mac::{MAC_MAXIMUM_INPUT, MacAlgorithm, MacCapabilities, MacKeyRequest};
mod symmetric;
pub use symmetric::{
    AES_BLOCK_SIZE, AES_MAXIMUM_INPUT, AesCipherCapabilities, AesDecryptRequest, AesDirection,
    AesEncryptRequest, AesMode,
};
mod generation;
pub use generation::{AesKeyPurpose, AesKeyRequest, AesKeySize, EcdhKeyPairRequest};
mod hkdf;
mod kbkdf;
pub use kbkdf::{KbkdfCapabilities, KbkdfMode, KbkdfOutput, KbkdfPrf, KbkdfRequest};
mod hybrid;
mod key_operations;
mod ml_dsa;
mod ml_kem;
pub use encryption::{RsaCipherOperation, RsaOaepCapabilities};
pub use hkdf::{HkdfCapabilities, HkdfOutput, HkdfRequest};
pub use key_operations::{EcdhDerivation, KeyOperation, KeyOperationProfile};
pub use ml_dsa::{
    MlDsaCapabilities, MlDsaHedging, MlDsaParameterSet, MlDsaPublicKey, MlDsaRequest,
    MlDsaSigningPolicy,
};
pub use ml_kem::{
    MlKemCapabilities, MlKemOperation, MlKemParameterSet, MlKemPublicKey, MlKemRequest,
};
mod pqc_hash;
pub use pqc_hash::{
    HashInput, HashMlDsaCapabilities, HashMlDsaRequest, HashMlDsaSigningPolicy,
    HashSlhDsaCapabilities, HashSlhDsaRequest, HashSlhDsaSigningPolicy, PrehashAlgorithm,
};
mod slh_dsa;
pub use slh_dsa::{
    SLH_DSA_MAXIMUM_MESSAGE, SlhDsaCapabilities, SlhDsaHedging, SlhDsaKeyPairRequest,
    SlhDsaParameterSet, SlhDsaPublicKey, SlhDsaRequest, SlhDsaSigningPolicy,
};
mod error;
mod module;
mod pool;
mod session;
mod signing;
pub use pool::{SessionLease, SessionPool};
pub use signing::*;
mod verification;
pub use verification::{VerificationCapabilities, VerifyRequest};

pub use error::Error;
pub use module::{Module, Token, validate_token_uri};
pub use session::{AttributeValues, Authentication, Object, ObjectRef, Pin, Session, SessionMode};
// Reuse cryptoki's domain representations, without exposing lifecycle or handles.
pub use cryptoki::{
    context::Function,
    context::Info as LibraryInfo,
    mechanism::{MechanismInfo, MechanismType},
    object::{Attribute, AttributeInfo, AttributeType, CertificateType, KeyType, ObjectClass},
    session::{SessionInfo, SessionState},
    slot::{Slot, SlotInfo, TokenInfo},
};
