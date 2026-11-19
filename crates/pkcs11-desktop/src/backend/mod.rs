// SPDX-License-Identifier: MIT OR Apache-2.0
mod administration;
pub use administration::{AdministrationAction, AdministrationKind};
mod authentication;
mod browse;
mod cipher;
mod hkdf;
mod kem;
pub use hkdf::HkdfJob;
mod key_operations;
pub use key_operations::{KeyJob, KeyProfile, MontgomeryKdfChoice, MontgomeryOutputChoice};
mod crypto;
pub use cipher::{AesGcmFiles, CipherJob, CipherParameters};
mod management;
mod random;
pub use authentication::{LoginRole, LoginState, SecretInput};
pub use browse::{MechanismEntry, MetadataField, ObjectDetails, ObjectEntry};
pub use crypto::{CryptoJob, CryptoMode, CryptoScope, SignatureOption, SignatureProfile};
pub use management::{GenerationKind, ManagementAction};

mod protocol;
mod registry;
mod worker;

#[cfg(test)]
pub use protocol::SyntheticOutcome;
pub use protocol::{
    BackendCommand, BackendError, BackendEvent, BackendResult, ModuleEntry, RequestId, ResourceId,
    SlotEntry, TokenEntry,
};
pub use worker::{EventSource, Worker};

use registry::{LoadedModule, Registry, finish_session};
#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod generation_tests;

#[cfg(test)]
mod gcm_tests;
