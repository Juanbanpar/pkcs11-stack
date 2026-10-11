// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod certificate;
mod client;
mod error;
mod management;

pub use certificate::{Certificate, CertificateDocument};
pub use client::{Client, Identity};
pub use error::{Error, ErrorKind};
pub use management::{
    AttributeRead, ManagementSession, MechanismSnapshot, PoolDiagnostic, Provider, SlotSnapshot,
    TokenSnapshot, object_reference, token_uri, validate_token_uri,
};
pub use pkcs11_locator::Pkcs11Uri;
pub use pkcs11_runtime::{
    Attribute, AttributeInfo, AttributeType, AttributeValues, Authentication, CertificateRef,
    DigestAlgorithm, HashLocation, HashingPolicy, KeyCapabilities, KeyKind, LibraryInfo,
    MechanismInfo, MechanismType, Module, NamedCurve, ObjectClass, ObjectRef, Pin, PrivateKeyRef,
    PssParameters, PublicKeyMetadata, PublicKeyRef, SessionMode, SessionPool, SessionState,
    SignInput, SignPlan, SignRequest, SignatureAlgorithm, SigningMechanism, SigningPolicy,
    SlotInfo, TokenInfo,
};
