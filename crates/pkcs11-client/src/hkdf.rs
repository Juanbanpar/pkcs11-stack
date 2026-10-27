// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    DigestAlgorithm, Error, HkdfCapabilities, HkdfMode, HkdfRequest, ManagementSession, ObjectRef,
};

impl ManagementSession<'_> {
    /// Use a token-held salt for HKDF extraction or extract-and-expand. Byte salt
    /// must be empty. Both locators resolve in the same session; salt keys must
    /// be sensitive, nonextractable generic/HKDF secrets of 1..=4096 bytes, with
    /// derivation permission and a permitted HKDF mechanism. No key bytes leave
    /// the token. Requires RW mode; check closure. No retry or rollback occurs.
    pub fn derive_hkdf_with_salt_key(
        &mut self,
        base: &ObjectRef,
        salt_key: &ObjectRef,
        request: &HkdfRequest<'_>,
        mode: HkdfMode,
    ) -> Result<(), Error> {
        Ok(self
            .session
            .derive_hkdf_with_salt_key(base, salt_key, request, mode)?)
    }

    /// Apply an explicit HKDF stage once on the token. Extract-only produces a
    /// hash-length PRK with derivation permission only. Expand-only requires the
    /// caller to establish that the selected base is a PRK; metadata cannot prove
    /// this. Disabled-stage parameters are rejected. Requires RW access and the
    /// existing sensitive, nonextractable hash-length generic/HKDF base profile.
    /// Check closure; failure may leave effects, without rollback or retry.
    pub fn derive_hkdf_with_mode(
        &mut self,
        base: &ObjectRef,
        request: &HkdfRequest<'_>,
        mode: HkdfMode,
    ) -> Result<(), Error> {
        Ok(self.session.derive_hkdf_with_mode(base, request, mode)?)
    }
    /// Discover SHA-2 HKDF profiles permitted by the selected base and provider.
    /// At most one digest matches the PKCS#11 hash-length base-key requirement.
    /// Unsupported profiles are omitted; selection, metadata and provider failures propagate.
    /// This reads capabilities only and never derives or reads a key value.
    pub fn hkdf_options(&mut self, base: &ObjectRef) -> Result<Vec<HkdfCapabilities>, Error> {
        Ok(self.session.hkdf_options(base)?)
    }
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
