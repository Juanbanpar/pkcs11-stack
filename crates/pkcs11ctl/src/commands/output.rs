// SPDX-License-Identifier: MIT OR Apache-2.0
use serde_json::Value;

pub(crate) enum Output {
    Structured(Value),
    Binary(Vec<u8>),
    SecretBinary(pkcs11_client::RandomBytes),
}
