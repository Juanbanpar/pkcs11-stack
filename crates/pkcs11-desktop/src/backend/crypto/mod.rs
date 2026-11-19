// SPDX-License-Identifier: MIT OR Apache-2.0
mod certificate;
mod operations;
mod options;
mod types;

pub use types::{CryptoJob, CryptoMode, CryptoScope, SignatureOption, SignatureProfile};

#[cfg(test)]
#[path = "eddsa_tests.rs"]
mod eddsa_tests;
#[cfg(test)]
#[path = "ml_dsa_tests.rs"]
mod ml_dsa_tests;
#[cfg(test)]
#[path = "pqc_tests.rs"]
mod pqc_tests;
#[cfg(test)]
#[path = "crypto_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "verification_tests.rs"]
mod verification_tests;
