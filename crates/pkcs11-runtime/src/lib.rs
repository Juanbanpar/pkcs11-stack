// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod capability;
mod derivation;
mod digest;
mod encryption;
mod error;
mod key_establishment;
mod key_management;
mod mac;
mod module;
mod objects;
mod secret;
mod session;
mod signing;

pub use capability::{
    FunctionAvailability, INTERFACE_FUNCTIONS, MechanismCapability, MechanismFamily,
    MechanismOperation, is_runtime_supported, mechanism_family,
};
pub use derivation::{
    HkdfCapabilities, HkdfOutput, HkdfRequest, KbkdfCapabilities, KbkdfMode, KbkdfOutput, KbkdfPrf,
    KbkdfRequest,
};
pub use digest::{DIGEST_MAXIMUM_INPUT, HashAlgorithm};
pub use encryption::{
    AES_BLOCK_SIZE, AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_PLAINTEXT, AES_GCM_NONCE_LENGTH,
    AES_GCM_TAG_LENGTH, AES_MAXIMUM_INPUT, AesCipherCapabilities, AesDecryptRequest, AesDirection,
    AesEncryptRequest, AesGcmCapabilities, AesGcmDecryptRequest, AesGcmEncryptRequest,
    AesGcmOperation, AesMode, RsaCipherOperation, RsaOaepCapabilities,
};
pub use error::Error;
pub use key_establishment::{
    EcdhDerivation, MlKemCapabilities, MlKemOperation, MlKemParameterSet, MlKemPublicKey,
    MlKemRequest, MontgomeryCapabilities, MontgomeryCurve, MontgomeryDerivation, MontgomeryKdf,
    MontgomeryOutput, MontgomeryPublicKey,
};
pub use key_management::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, EcdhKeyPairRequest, KeyOperation, KeyOperationProfile,
};
pub use mac::{MAC_MAXIMUM_INPUT, MacAlgorithm, MacCapabilities, MacKeyRequest};
pub use module::{Module, Token, validate_token_uri};
pub use objects::{
    AttributeValues, CertificateRef, KeyKind, NamedCurve, Object, ObjectRef, PrivateKeyRef,
    PublicKeyMetadata, PublicKeyRef,
};
pub use pkcs11_locator::SecretText;
pub use secret::SecretBytes;
pub use session::{Authentication, Pin, Session, SessionLease, SessionMode, SessionPool};
pub use signing::{
    DigestAlgorithm, EdDsaCapabilities, EdDsaCurve, EdDsaPublicKey, EdDsaRequest, HashInput,
    HashLocation, HashMlDsaCapabilities, HashMlDsaRequest, HashMlDsaSigningPolicy,
    HashSlhDsaCapabilities, HashSlhDsaRequest, HashSlhDsaSigningPolicy, HashingPolicy,
    KeyCapabilities, MlDsaCapabilities, MlDsaHedging, MlDsaParameterSet, MlDsaPublicKey,
    MlDsaRequest, MlDsaSigningPolicy, PrehashAlgorithm, PssParameters, SLH_DSA_MAXIMUM_MESSAGE,
    SignInput, SignPlan, SignRequest, SignatureAlgorithm, SigningMechanism, SigningPolicy,
    SlhDsaCapabilities, SlhDsaHedging, SlhDsaKeyPairRequest, SlhDsaParameterSet, SlhDsaPublicKey,
    SlhDsaRequest, SlhDsaSigningPolicy, VerificationCapabilities, VerifyRequest,
};
// Reuse cryptoki domain representations without exposing lifecycle owners or handles.
pub use cryptoki::{
    context::Function,
    context::Info as LibraryInfo,
    mechanism::{MechanismInfo, MechanismType},
    object::{Attribute, AttributeInfo, AttributeType, CertificateType, KeyType, ObjectClass},
    session::{SessionInfo, SessionState},
    slot::{Slot, SlotInfo, TokenInfo},
};
