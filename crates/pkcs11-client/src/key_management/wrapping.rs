// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, ManagementSession, ObjectRef, SecretKeyIdentity};

/// RFC 3394 wrap request; the selected target must be an extractable AES key.
pub struct WrapRequest<'a> {
    /// Freshly resolved persistent target; no key value is read by the client.
    pub target: &'a ObjectRef,
}
/// RFC 3394 unwrap request; ciphertext contains key bytes only, without metadata.
pub struct UnwrapRequest<'a> {
    /// Exactly 24/32/40 bytes for AES-128/192/256 respectively.
    pub wrapped: &'a [u8],
    /// New sensitive, nonextractable private secret key identity.
    pub identity: SecretKeyIdentity<'a>,
}

super::redacted_request!(WrapRequest, UnwrapRequest);

impl ManagementSession<'_> {
    /// Wrap an AES key once with RFC 3394; no template override or extractability change.
    pub fn wrap(
        &mut self,
        wrapping: &ObjectRef,
        request: &WrapRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.wrap_aes_key(wrapping, request.target)?)
    }
    /// Unwrap once into a persistent private AES encryption/decryption key.
    /// No automatic retry or rollback; even a reported failure can have token effects.
    pub fn unwrap(
        &mut self,
        unwrapping: &ObjectRef,
        request: &UnwrapRequest<'_>,
    ) -> Result<(), Error> {
        Ok(self.session.unwrap_aes_key(
            unwrapping,
            request.wrapped,
            request.identity.id,
            request.identity.label,
        )?)
    }
}
