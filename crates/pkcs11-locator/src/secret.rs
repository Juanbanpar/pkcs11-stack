// SPDX-License-Identifier: MIT OR Apache-2.0
use secrecy::{ExposeSecret, SecretBox};
use std::fmt;

/// Owned secret text with redacted debug output and storage wiped on drop.
#[derive(Default)]
pub struct SecretText(SecretBox<String>);

impl SecretText {
    /// Borrow the text explicitly. Any copies made by the caller need their own protection.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl From<String> for SecretText {
    fn from(value: String) -> Self {
        Self(SecretBox::new(Box::new(value)))
    }
}

impl From<&str> for SecretText {
    fn from(value: &str) -> Self {
        Self::from(value.to_owned())
    }
}

impl Clone for SecretText {
    fn clone(&self) -> Self {
        Self::from(self.expose_secret())
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText([REDACTED])")
    }
}
