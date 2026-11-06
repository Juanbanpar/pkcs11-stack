// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod administration;
mod aes_cmac;
pub use pkcs11_runtime::{
    AES_CMAC_MAXIMUM_MESSAGE, AES_CMAC_TAG_LENGTH, AesCmacCapabilities, AesCmacOptions,
    AesCmacProfile, MacOperation,
};
mod aes_gcm;
mod aes_gcm_message;
mod aes_gcm_stream;
pub use administration::TokenInitializationTarget;
pub use aes_gcm::{
    AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_PLAINTEXT, AES_GCM_NONCE_LENGTH, AES_GCM_TAG_LENGTH,
    AesGcmCapabilities, AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmOperation,
};
pub use aes_gcm_message::{AesGcmMessageDecryption, AesGcmMessageEncryption};
pub use aes_gcm_stream::{AesGcmDecryption, AesGcmEncryption};
pub use pkcs11_runtime::AesGcmStreamParameters;
mod certificate;
mod digest;
mod eddsa;
mod eddsa_named;
pub use eddsa_named::EdDsaNamedPublicKey;
mod montgomery_kdf;
pub use montgomery_kdf::{MontgomeryKdfRequest, MontgomeryOutput};
mod montgomery_named;
pub use montgomery_named::{
    MontgomeryNamedCurve, MontgomeryNamedKeyPairRequest, MontgomeryNamedPeer,
    MontgomeryNamedRequest,
};
mod x448;
pub use pkcs11_runtime::{X448Kdf, X448KeyPairRequest, X448Output, X448PublicKey};
pub use x448::{X448Peer, X448Request};
mod x25519;
pub use pkcs11_runtime::{X25519KeyPairRequest, X25519PublicKey};
pub use x25519::{X25519Peer, X25519Request};
mod eddsa_certificate;
pub use digest::DigestOperation;
pub use eddsa::EdDsaVerifyingKey;
pub use eddsa_certificate::{EdDsaCertificate, EdDsaIdentity};
pub use pkcs11_runtime::{CancelFlags, DigestMode, HashAlgorithm};
pub use pkcs11_runtime::{
    EdDsaCapabilities, EdDsaCurve, EdDsaNamedRequest, EdDsaNamedScheme, EdDsaRequest,
};
mod encryption;
mod key_operations;
pub use encryption::{DecryptRequest, EncryptRequest, OaepChoice, Plaintext};
pub use key_operations::{
    AesKeyWrapAlgorithm, AesKeyWrapCapabilities, DeriveRequest, EcdhKdf, EcdhOutput, EcdhPeer,
    EcdhRequest, KeyOperation, KeyOperationProfile, SecretKeyIdentity, UnwrapRequest, WrapRequest,
};
pub use pkcs11_runtime::{RsaCipherOperation, RsaOaepParameters};
mod client;
mod error;
mod generation;
pub use generation::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, EcdhKeyPairRequest, GenerationCapabilities,
    RsaEncryptionKeyPairRequest,
};
mod hkdf;
mod kbkdf;
mod pbkdf2;
pub use pkcs11_runtime::{
    KbkdfCapabilities, KbkdfMode, KbkdfOptions, KbkdfOutput, KbkdfPrf, KbkdfPrfCapabilities,
    KbkdfPrfRequest, KbkdfRequest,
};
pub use pkcs11_runtime::{
    PBKDF2_MAXIMUM_LENGTH, PBKDF2_MAXIMUM_WORK, Pbkdf2Output, Pbkdf2Prf, Pbkdf2Request,
};
mod hmac;
mod mac;
pub use mac::{MacGeneration, MacVerification};
pub use pkcs11_runtime::{
    HMAC_MAXIMUM_MESSAGE, HmacAlgorithm, HmacCapabilities, HmacKeyRequest, HmacOptions,
    HmacTagProfile,
};
mod hash_slh_dsa;
pub use hash_slh_dsa::{
    HashSlhDsaCapabilities, HashSlhDsaInput, HashSlhDsaMode, HashSlhDsaRequest,
};
pub use pkcs11_runtime::HashSlhDsaSigningPolicy;
mod hash_ml_dsa;
mod hash_ml_dsa_stream;
pub use hash_ml_dsa_stream::{
    HashMlDsaParameters, HashMlDsaProfileParameters, HashMlDsaVerificationCapabilities,
    HashMlDsaVerificationOperation,
};
mod management;
mod slh_dsa;
pub use pkcs11_runtime::{
    SLH_DSA_MAXIMUM_MESSAGE, SlhDsaCapabilities, SlhDsaHedging, SlhDsaKeyPairRequest,
    SlhDsaParameterSet, SlhDsaPublicKey, SlhDsaRequest, SlhDsaSigningPolicy,
};
mod ml_dsa;
pub use hash_ml_dsa::{HashMlDsaCapabilities, HashMlDsaInput, HashMlDsaMode, HashMlDsaRequest};
mod ml_dsa_stream;
pub use ml_dsa_stream::{MlDsaSigningOperation, MlDsaVerificationOperation};
pub use pkcs11_runtime::{MlDsaParameters, MlDsaVerificationCapabilities};
mod ml_dsa_certificate;
mod ml_kem;
pub use ml_dsa_certificate::{MlDsaCertificate, MlDsaIdentity, MlDsaVerifyingKey};
pub use ml_kem::MlKemPublicKey;
pub use pkcs11_runtime::{HkdfCapabilities, HkdfMode, HkdfOutput, HkdfRequest};
pub use pkcs11_runtime::{
    MlDsaCapabilities, MlDsaHedging, MlDsaParameterSet, MlDsaPublicKey, MlDsaRequest,
    MlDsaSigningPolicy,
};
pub use pkcs11_runtime::{MlKemCapabilities, MlKemOperation, MlKemParameterSet, MlKemRequest};
mod object_locator;
mod public_export;
mod public_import;
mod public_metadata;
mod template_metadata;
pub use pkcs11_runtime::{
    TEMPLATE_METADATA_MAX_BYTES, TEMPLATE_METADATA_MAX_DEPTH, TEMPLATE_METADATA_MAX_MEMBERS,
    TemplateAttribute, TemplateMember, TemplateMetadata,
};
pub use public_import::{ClassicalPublicKey, ClassicalPublicKeyPurpose, PublicKeyImportRequest};
pub use public_metadata::{PUBLIC_METADATA_FIELDS, PUBLIC_METADATA_MAX_ATTRIBUTE};
mod input;
mod random;
mod signature_options;
mod signature_stream;
pub use signature_stream::{SigningOperation, VerificationOperation};

pub use certificate::{Certificate, CertificateDocument};
pub use client::{Client, Identity};
pub use error::{Error, ErrorKind};
pub use management::{
    AttributeRead, ManagementSession, MechanismSnapshot, PoolDiagnostic, Provider, SlotSnapshot,
    TokenSnapshot, object_reference, token_uri, validate_token_uri,
};
pub use object_locator::object_locator;
pub use pkcs11_locator::Pkcs11Uri;
pub use pkcs11_runtime::{
    Attribute, AttributeInfo, AttributeType, AttributeValues, Authentication,
    CLASSICAL_SIGNATURE_MAXIMUM_LENGTH, CertificateRef, DigestAlgorithm, Function, HashLocation,
    HashingPolicy, InterfaceInfo, InterfaceSelection, InterfaceVersion, KeyCapabilities, KeyKind,
    KeyType, LibraryInfo, MechanismInfo, MechanismType, Module, ModuleOptions, NamedCurve,
    ObjectClass, ObjectRef, Pin, PrivateKeyRef, PssParameters, PublicKeyMetadata, PublicKeyRef,
    SessionMode, SessionPool, SessionState, SignInput, SignPlan, SignRequest, SignatureAlgorithm,
    SignatureParameters, SigningMechanism, SigningPolicy, SlotInfo, TokenInfo,
    VerificationCapabilities, VerifyRequest,
};
pub use random::{RandomBytes, RandomRequest};
pub use signature_options::{SigningChoice, SigningOptions};
