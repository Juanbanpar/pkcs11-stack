// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod administration;
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
