// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, Provider, TokenSnapshot};
use secrecy::{ExposeSecret, SecretString};

/// Metadata that must still match before initializing one explicitly selected slot.
/// This is a snapshot, not an authorization token or physical device identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenInitializationTarget {
    /// Current diagnostic slot ID; never persist it as token identity.
    pub slot_id: u64,
    /// Observed token label.
    pub label: String,
    /// Observed manufacturer.
    pub manufacturer: String,
    /// Observed model.
    pub model: String,
    /// Observed serial, which may be empty on an uninitialized token.
    pub serial: String,
    /// Whether this snapshot already contained initialized token contents.
    pub initialized: bool,
    /// Advertised minimum PIN length in bytes; usize::MAX means unavailable.
    pub minimum_pin_length: usize,
    /// Advertised maximum PIN length in bytes; usize::MAX means unavailable.
    pub maximum_pin_length: usize,
}
impl TokenInitializationTarget {
    /// Validate a nonempty new host PIN against available advertised byte bounds.
    /// A provider may impose additional constraints; no PIN is formatted or retained.
    pub fn accepts_new_pin(&self, pin: &SecretString) -> bool {
        let length = pin.expose_secret().len();
        length != 0
            && (self.minimum_pin_length == usize::MAX || length >= self.minimum_pin_length)
            && (self.maximum_pin_length == usize::MAX || length <= self.maximum_pin_length)
    }
}
impl TokenSnapshot {
    /// Capture slot, token identity, initialized state and PIN bounds for confirmation.
    pub fn initialization_target(&self) -> TokenInitializationTarget {
        TokenInitializationTarget {
            slot_id: self.slot_id,
            label: self.info.label().into(),
            manufacturer: self.info.manufacturer_id().into(),
            model: self.info.model().into(),
            serial: self.info.serial_number().into(),
            initialized: self.info.token_initialized(),
            minimum_pin_length: self.info.min_pin_length(),
            maximum_pin_length: self.info.max_pin_length(),
        }
    }
}
impl Provider {
    /// Initialize/erase only if the confirmed slot and token snapshot still match.
    /// Requires exclusive module ownership; close all consumers first. Host SO PIN only.
    /// Identical replacement devices and swaps after the check cannot be detected;
    /// callers must arrange exclusive physical access. No retry or rollback occurs.
    pub fn initialize_token_checked(
        &mut self,
        target: &TokenInitializationTarget,
        so_pin: &SecretString,
        label: &str,
    ) -> Result<(), Error> {
        if std::sync::Arc::get_mut(&mut self.module).is_none() {
            return Err(Error::ProviderInUse);
        }
        let current = self
            .tokens()?
            .into_iter()
            .find(|token| token.slot_id == target.slot_id)
            .ok_or(pkcs11_runtime::Error::TokenChanged)?;
        if current.initialization_target() != *target {
            return Err(pkcs11_runtime::Error::TokenChanged.into());
        }
        self.initialize_token(target.slot_id, so_pin, label)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_pin_bounds_use_bytes_and_never_require_formatting_the_pin() {
        let mut target = TokenInitializationTarget {
            slot_id: 1,
            label: "token".into(),
            manufacturer: "vendor".into(),
            model: "model".into(),
            serial: "serial".into(),
            initialized: true,
            minimum_pin_length: 4,
            maximum_pin_length: 8,
        };
        assert!(target.accepts_new_pin(&"1234".into()));
        assert!(target.accepts_new_pin(&"éé".into()));
        for pin in ["", "123", "123456789"] {
            assert!(!target.accepts_new_pin(&pin.into()));
        }
        target.minimum_pin_length = usize::MAX;
        target.maximum_pin_length = usize::MAX;
        assert!(target.accepts_new_pin(&"1".into()));
        assert!(!target.accepts_new_pin(&"".into()));
    }
}
