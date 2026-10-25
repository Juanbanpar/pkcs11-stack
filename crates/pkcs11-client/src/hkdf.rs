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
    /// Combine distinct P-256 and ML-KEM-768 token secrets using classical || PQ,
    /// then run HKDF-SHA512. Both selected inputs must be sensitive, nonextractable
    /// 32-byte generic secrets permitting derivation. The caller establishes their
    /// origin, independence and peer trust; metadata cannot prove provenance.
    /// Public salt is at most 128 bytes and protocol context must be nonempty.
    /// The concatenation is temporary; only the requested output persists.
    /// This is an application combiner, not X-Wing or the TLS key schedule.
    /// No values are read, no base is deleted, and no retry or rollback occurs.
    /// Check session closure on every result; cleanup failure takes precedence.
    pub fn derive_hybrid_hkdf(
        &mut self,
        classical: &ObjectRef,
        post_quantum: &ObjectRef,
        request: &HkdfRequest<'_>,
    ) -> Result<(), Error> {
        Ok(self
            .session
            .derive_hybrid_hkdf(classical, post_quantum, request)?)
    }
}
