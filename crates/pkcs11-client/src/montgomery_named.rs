// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, ManagementSession, ObjectRef, SecretKeyIdentity};
pub use pkcs11_runtime::MontgomeryNamedCurve;
use pkcs11_runtime::MontgomeryNamedPublicKey;

/// Checked raw public input for an explicit RFC 7748 curveName profile.
/// Does not authenticate ownership. This API does not interpret or emit SPKI.
#[derive(Clone, Debug)]
pub struct MontgomeryNamedPeer(MontgomeryNamedPublicKey);
impl MontgomeryNamedPeer {
    /// Validate exactly 32/56 raw little-endian bytes, including noncontributory
    /// point rejection. Preserves RFC 7748 encoding aliases for the provider.
    pub fn from_bytes(curve: MontgomeryNamedCurve, bytes: &[u8]) -> Result<Self, Error> {
        MontgomeryNamedPublicKey::from_bytes(curve, bytes)
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }
    /// Explicitly selected curveName profile.
    pub fn curve(&self) -> MontgomeryNamedCurve {
        self.0.curve()
    }
    /// Original raw public bytes, without ASN.1 wrapping.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
/// Persistent curveName pair with a protected derivation-only private key.
pub struct MontgomeryNamedKeyPairRequest<'a> {
    /// Explicit RFC 7748 curveName profile.
    pub curve: MontgomeryNamedCurve,
    /// Shared nonempty public/private ID, at most 128 bytes.
    pub id: &'a [u8],
    /// Shared nonempty label, at most 128 bytes.
    pub label: &'a [u8],
}
impl MontgomeryNamedKeyPairRequest<'_> {
    /// Validate identity bounds without provider access.
    pub fn validate(&self) -> Result<(), Error> {
        identity(self.id, self.label)
    }
}
impl std::fmt::Debug for MontgomeryNamedKeyPairRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MontgomeryNamedKeyPairRequest([REDACTED])")
    }
}
/// Raw curveName agreement; the full 32/56-byte secret remains on the token.
pub struct MontgomeryNamedRequest<'a> {
    /// Checked raw peer input. Callers must authenticate ownership separately.
    pub peer: &'a MontgomeryNamedPeer,
    /// New private, sensitive, nonextractable derivation-only secret identity.
    pub identity: SecretKeyIdentity<'a>,
}
impl MontgomeryNamedRequest<'_> {
    /// Validate identity bounds without provider access.
    pub fn validate(&self) -> Result<(), Error> {
        identity(self.identity.id, self.identity.label)
    }
}
impl std::fmt::Debug for MontgomeryNamedRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MontgomeryNamedRequest([REDACTED])")
    }
}
fn identity(id: &[u8], label: &[u8]) -> Result<(), Error> {
    if id.is_empty() || id.len() > 128 || label.is_empty() || label.len() > 128 {
        return Err(pkcs11_runtime::Error::InvalidParameters(
            "key ID and label must each contain 1..=128 bytes",
        )
        .into());
    }
    Ok(())
}
impl ManagementSession<'_> {
    /// Generate a persistent curveName pair with sensitive/nonextractable private
    /// material restricted to ECDH derivation. Requires RW mode and new public/
    /// private IDs. Concurrent writers can race; failures may leave objects.
    /// No retry/rollback. Check session closure before releasing results.
    pub fn generate_named_montgomery_key_pair(
        &mut self,
        request: &MontgomeryNamedKeyPairRequest<'_>,
    ) -> Result<(), Error> {
        request.validate()?;
        self.session.generate_named_montgomery_key_pair(
            request.curve,
            request.id,
            request.label,
        )?;
        Ok(())
    }
    /// Import raw public input as a public, untrusted curveName object with all
    /// operation permissions disabled. Requires RW mode, bounded identity and a
    /// new public ID. Does not associate a private key or authenticate ownership.
    /// Concurrent writers can race; no retry/rollback. Check session closure.
    pub fn import_named_montgomery_public_key(
        &mut self,
        key: &MontgomeryNamedPeer,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        identity(id, label)?;
        self.session
            .import_named_montgomery_public_key(&key.0, id, label)?;
        Ok(())
    }
    /// Export bounded public metadata as raw little-endian bytes, requiring
    /// exactly the selected curveName profile. RFC 8410 OID keys are rejected.
    /// Does not request private/secret values or establish trust.
    pub fn export_named_montgomery_public_key(
        &mut self,
        key: &ObjectRef,
        curve: MontgomeryNamedCurve,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .session
            .named_montgomery_public_key(key, curve)?
            .as_bytes()
            .to_vec())
    }
    /// Derive once with CKD_NULL from a matching, protected curveName private
    /// key. Requires RW mode; returns no private/shared-secret bytes. The full
    /// persistent 32/56-byte result permits further derivation only. Apply a
    /// protocol KDF separately: curve448's 56 bytes cannot feed HKDF-SHA512's
    /// hash-length input profile; SP 800-108 accepts either width.
    /// Authenticate peers and check closure; no retry/rollback after failure.
    pub fn derive_named_montgomery(
        &mut self,
        base: &ObjectRef,
        request: &MontgomeryNamedRequest<'_>,
    ) -> Result<(), Error> {
        request.validate()?;
        Ok(self.session.derive_named_montgomery_secret(
            base,
            &request.peer.0,
            request.identity.id,
            request.identity.label,
        )?)
    }
}
