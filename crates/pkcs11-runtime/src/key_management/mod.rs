// SPDX-License-Identifier: MIT OR Apache-2.0
mod generation;

pub use generation::{AesKeyPurpose, AesKeyRequest, AesKeySize, EcdhKeyPairRequest};

mod templates;
mod wrapping;

use crate::{AttributeType, Error, NamedCurve, ObjectRef, Session, key_establishment::ecdh_curve};

pub(crate) use templates::validate_secret_identity;

/// Supported token key derivation and transfer operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOperation {
    /// Raw ECDH, producing token-held generic secret material for a later KDF.
    Derive,
    /// RFC 3394 AES key wrap, with the default IV.
    Wrap,
    /// RFC 3394 AES key unwrap, creating a private nonextractable AES key.
    Unwrap,
}
/// Advisory profile after current class, permission and mechanism checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOperationProfile {
    /// ECDH on this curve with an explicitly selected null KDF.
    EcdhRaw(NamedCurve),
    /// RFC 3394 using an AES wrapping key of this length in bytes.
    AesKeyWrap(usize),
}

impl Session<'_> {
    /// Inspect a uniquely resolved key. Advertised KDF/profile support is advisory.
    pub fn key_operation_profile(
        &mut self,
        key: &ObjectRef,
        operation: KeyOperation,
    ) -> Result<KeyOperationProfile, Error> {
        let object = self.resolve(key)?;
        match operation {
            KeyOperation::Derive => ecdh_curve(&object).map(KeyOperationProfile::EcdhRaw),
            KeyOperation::Wrap => {
                wrapping::check_aes_wrap_key(&object, AttributeType::Wrap, |info| info.wrap())
                    .map(KeyOperationProfile::AesKeyWrap)
            }
            KeyOperation::Unwrap => {
                wrapping::check_aes_wrap_key(&object, AttributeType::Unwrap, |info| info.unwrap())
                    .map(KeyOperationProfile::AesKeyWrap)
            }
        }
    }
}
