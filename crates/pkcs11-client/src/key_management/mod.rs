// SPDX-License-Identifier: MIT OR Apache-2.0
mod generation;
mod wrapping;
pub(crate) use generation::choices;

pub use generation::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, EcdhKeyPairRequest, GenerationCapabilities,
};

use crate::{Error, ManagementSession, ObjectRef};
pub use pkcs11_runtime::{KeyOperation, KeyOperationProfile};
pub use wrapping::{UnwrapRequest, WrapRequest};

macro_rules! redacted_request { ($($name:ident),+) => { $(impl std::fmt::Debug for $name<'_> { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(concat!(stringify!($name), "([REDACTED])")) } })+ }; }
pub(crate) use redacted_request;

/// Persistent identity for a newly created secret key; bounded to 128 bytes per field.
#[derive(Clone, Copy)]
pub struct SecretKeyIdentity<'a> {
    /// Nonempty CKA_ID; an existing secret key with this ID is rejected.
    pub id: &'a [u8],
    /// Nonempty CKA_LABEL.
    pub label: &'a [u8],
}
redacted_request!(SecretKeyIdentity);

impl ManagementSession<'_> {
    /// Advisory profile after current key, permission and provider checks, with no mutation.
    pub fn key_operation_options(
        &mut self,
        key: &ObjectRef,
        operation: KeyOperation,
    ) -> Result<KeyOperationProfile, Error> {
        Ok(self.session.key_operation_profile(key, operation)?)
    }
}
