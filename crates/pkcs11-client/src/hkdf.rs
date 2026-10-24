// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{DigestAlgorithm, Error, HkdfCapabilities, HkdfRequest, ManagementSession, ObjectRef};

impl ManagementSession<'_> {
    /// Inspect the selected base key and HKDF mechanism without deriving.
    /// The sensitive, nonextractable generic/HKDF base must match the hash length.
    pub fn hkdf_capabilities(
        &mut self,
        base: &ObjectRef,
        digest: DigestAlgorithm,
    ) -> Result<HkdfCapabilities, Error> {
        Ok(self.session.hkdf_capabilities(base, digest)?)
    }
    /// Apply token-side HKDF extract-and-expand once in an RW session.
    /// Creates a persistent private, sensitive, nonextractable key with only the
    /// requested output profile's permissions. Existing secret IDs are rejected.
    /// Base and output values never leave the token; no software fallback or retry.
    /// The caller supplies public salt/context and authenticates the peer.
    /// Close the session to check cleanup; failures can leave persistent effects.
    pub fn derive_hkdf(
        &mut self,
        base: &ObjectRef,
        request: &HkdfRequest<'_>,
    ) -> Result<(), Error> {
        Ok(self.session.derive_hkdf(base, request)?)
    }
}
