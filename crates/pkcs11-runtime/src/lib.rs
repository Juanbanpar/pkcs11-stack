// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod administration;
mod encryption;
mod key_operations;
mod ml_dsa;
mod ml_kem;
pub use encryption::{RsaCipherOperation, RsaOaepCapabilities};
pub use key_operations::{EcdhDerivation, KeyOperation, KeyOperationProfile};
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
pub use pool::{SessionLease, SessionPool};
pub use signing::*;

pub use error::Error;
pub use module::{Module, Token, validate_token_uri};
pub use session::{AttributeValues, Authentication, Object, ObjectRef, Pin, Session, SessionMode};
// Reuse cryptoki's domain representations, without exposing lifecycle or handles.
pub use cryptoki::{
    context::Info as LibraryInfo,
    mechanism::{MechanismInfo, MechanismType},
    object::{Attribute, AttributeInfo, AttributeType, CertificateType, ObjectClass},
    session::{SessionInfo, SessionState},
    slot::{Slot, SlotInfo, TokenInfo},
};
