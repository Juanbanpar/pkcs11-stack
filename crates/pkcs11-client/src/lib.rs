// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod administration;
mod capability;
mod certificate;
mod client;
mod derivation;
mod digest;
mod encryption;
mod error;
mod key_establishment;
mod key_management;
mod mac;
mod management;
mod object_locator;
mod objects;
mod public_key;
mod random;
mod signing;

pub use administration::TokenInitializationTarget;
pub use certificate::{
    Certificate, CertificateDocument, EdDsaCertificate, EdDsaIdentity, MlDsaCertificate,
    MlDsaIdentity,
};
pub use client::{Client, Identity};
pub use encryption::{
    AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_PLAINTEXT, AES_GCM_NONCE_LENGTH, AES_GCM_TAG_LENGTH,
    AesGcmCapabilities, AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmOperation,
    DecryptRequest, EncryptRequest, OaepChoice, Plaintext,
};
pub use error::{Error, ErrorKind};
pub use key_establishment::{DeriveRequest, EcdhPeer, MlKemPublicKey};
pub use key_management::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, EcdhKeyPairRequest, GenerationCapabilities,
    KeyOperation, KeyOperationProfile, SecretKeyIdentity, UnwrapRequest, WrapRequest,
};
pub use management::{
    AttributeRead, ManagementSession, MechanismSnapshot, PoolDiagnostic, Provider, SlotSnapshot,
    TokenSnapshot, object_reference, token_uri, validate_token_uri,
};
pub use object_locator::object_locator;
pub use pkcs11_locator::Pkcs11Uri;
pub use pkcs11_runtime::RsaCipherOperation;
pub use pkcs11_runtime::{
    AES_BLOCK_SIZE, AES_MAXIMUM_INPUT, AesCipherCapabilities, AesDecryptRequest, AesDirection,
    AesEncryptRequest, AesMode, FunctionAvailability, HashAlgorithm, HashInput,
    HashMlDsaCapabilities, HashMlDsaRequest, HashMlDsaSigningPolicy, HashSlhDsaCapabilities,
    HashSlhDsaRequest, HashSlhDsaSigningPolicy, KbkdfCapabilities, KbkdfMode, KbkdfOutput,
    KbkdfPrf, KbkdfRequest, MacAlgorithm, MacCapabilities, MacKeyRequest, MechanismCapability,
    MechanismFamily, MechanismOperation, MontgomeryCapabilities, MontgomeryCurve,
    MontgomeryDerivation, MontgomeryKdf, MontgomeryOutput, MontgomeryPublicKey, PrehashAlgorithm,
    SlhDsaCapabilities, SlhDsaHedging, SlhDsaKeyPairRequest, SlhDsaParameterSet, SlhDsaPublicKey,
    SlhDsaRequest, SlhDsaSigningPolicy, VerificationCapabilities, VerifyRequest,
};
pub use pkcs11_runtime::{
    Attribute, AttributeInfo, AttributeType, AttributeValues, Authentication, CertificateRef,
    DigestAlgorithm, EdDsaCapabilities, EdDsaCurve, EdDsaPublicKey, EdDsaRequest, HashLocation,
    HashingPolicy, KeyCapabilities, KeyKind, KeyType, LibraryInfo, MechanismInfo, MechanismType,
    Module, NamedCurve, ObjectClass, ObjectRef, Pin, PrivateKeyRef, PssParameters,
    PublicKeyMetadata, PublicKeyRef, SessionMode, SessionPool, SessionState, SignInput, SignPlan,
    SignRequest, SignatureAlgorithm, SigningMechanism, SigningPolicy, SlotInfo, TokenInfo,
};
pub use pkcs11_runtime::{HkdfCapabilities, HkdfOutput, HkdfRequest};
pub use pkcs11_runtime::{
    MlDsaCapabilities, MlDsaHedging, MlDsaParameterSet, MlDsaPublicKey, MlDsaRequest,
    MlDsaSigningPolicy,
};
pub use pkcs11_runtime::{MlKemCapabilities, MlKemOperation, MlKemParameterSet, MlKemRequest};
pub use pkcs11_runtime::{SecretBytes, SecretText};
pub use public_key::{ClassicalPublicKey, ClassicalPublicKeyPurpose, PublicKeyImportRequest};
pub use random::{RandomBytes, RandomRequest};
pub use signing::{
    EdDsaVerifyingKey, MlDsaVerifyingKey, SignatureParameters, SigningChoice, SigningOptions,
};
