// SPDX-License-Identifier: MIT OR Apache-2.0
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
