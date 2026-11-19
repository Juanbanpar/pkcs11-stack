// SPDX-License-Identifier: MIT OR Apache-2.0
mod eddsa;
mod ml_dsa;
mod options;
mod slh_dsa;
mod verification;
pub(crate) use options::{candidates, options};

pub use eddsa::EdDsaVerifyingKey;
pub use ml_dsa::MlDsaVerifyingKey;
pub use options::{SignatureParameters, SigningChoice, SigningOptions};
