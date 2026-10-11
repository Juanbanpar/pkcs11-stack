// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod codec;
mod matcher;
mod uri;

pub use matcher::{
    ModuleIdentity, ModuleSelector, ObjectIdentity, ObjectSelector, ResourceIdentity, SlotIdentity,
    SlotSelector, TokenIdentity, TokenSelector,
};
pub use uri::{Error, ObjectType, Pkcs11Uri, Pkcs11UriBuilder};
