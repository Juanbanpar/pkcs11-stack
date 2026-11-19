// SPDX-License-Identifier: MIT OR Apache-2.0
mod certificate;
mod classical;
mod dispatch;
pub(crate) mod eddsa;
pub(crate) mod ml_dsa;
pub(crate) mod prehash;
mod request;
pub(crate) mod slh_dsa;

pub(crate) use certificate::{VerificationCertificate, verify};
pub(super) use dispatch::run;
pub(crate) use request::{Inputs, digest, request};
