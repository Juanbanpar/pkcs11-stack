// SPDX-License-Identifier: MIT OR Apache-2.0
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use std::fmt;

/// Owned secret bytes with redacted debug output and storage wiped on drop.
pub struct SecretBytes(SecretBox<Vec<u8>>);

impl SecretBytes {
    /// Borrow the bytes explicitly. Any copies made by the caller need their own protection.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Borrow the bytes for in-place writes.
    pub fn expose_secret_mut(&mut self) -> &mut [u8] {
        self.0.expose_secret_mut()
    }

    /// Shorten the visible slice. The full allocation is wiped on drop.
    pub fn truncate(&mut self, len: usize) {
        self.0.expose_secret_mut().truncate(len);
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(value)))
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}
