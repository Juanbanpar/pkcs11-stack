// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit RFC 7748 curveName profiles from PKCS #11 sections 6.3.7–6.3.8.
//! These token objects are incompatible with the RFC 8410 OID profiles. Public
//! input/output uses raw little-endian bytes, without SPKI conversion.
use crate::{
    Error, Object, ObjectRef, Session, Token, X448PublicKey, X25519PublicKey,
    key_operations::validate_secret_identity,
};
use cryptoki::mechanism::elliptic_curve::EcKdf;

/// RFC 7748 curveName encoding in CKA_EC_PARAMS, distinct from RFC 8410 OIDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MontgomeryNamedCurve {
    /// DER PrintableString "curve25519", with 32-byte public input/output.
    Curve25519,
    /// DER PrintableString "curve448", with 56-byte public input/output.
    Curve448,
}
impl MontgomeryNamedCurve {
    fn curve(self) -> crate::montgomery::Curve {
        match self {
            Self::Curve25519 => crate::montgomery::Curve::Curve25519,
            Self::Curve448 => crate::montgomery::Curve::Curve448,
        }
    }
}

/// Checked raw public input for an explicitly selected RFC 7748 token profile.
/// Does not authenticate the peer. Preserves RFC 7748 field encoding aliases;
/// rejects incorrect lengths and noncontributory points before provider access.
#[derive(Clone, PartialEq, Eq)]
pub struct MontgomeryNamedPublicKey {
    curve: MontgomeryNamedCurve,
    bytes: Vec<u8>,
}
impl MontgomeryNamedPublicKey {
    /// Validate raw public bytes for the selected curveName profile.
    pub fn from_bytes(curve: MontgomeryNamedCurve, bytes: &[u8]) -> Result<Self, Error> {
        match curve {
            MontgomeryNamedCurve::Curve25519 => {
                X25519PublicKey::from_bytes(bytes)?;
            }
            MontgomeryNamedCurve::Curve448 => {
                X448PublicKey::from_bytes(bytes)?;
            }
        }
        Ok(Self {
            curve,
            bytes: bytes.to_vec(),
        })
    }
    /// The explicitly selected curveName profile.
    pub fn curve(&self) -> MontgomeryNamedCurve {
        self.curve
    }
    /// Original raw little-endian public input, without ASN.1 wrapping.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl std::fmt::Debug for MontgomeryNamedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MontgomeryNamedPublicKey([REDACTED])")
    }
}

impl Token<'_> {
    /// Advertised generation support, including native entry point, flag and
    /// field-bit bounds. Advisory: curveName template acceptance is checked on use.
    pub fn named_montgomery_generation_supported(
        &self,
        curve: MontgomeryNamedCurve,
    ) -> Result<bool, Error> {
        crate::montgomery::generation_supported(self, curve.curve())
    }
}

impl<'m> Session<'m> {
    /// Generate a persistent curveName pair with a sensitive, nonextractable
    /// derivation-only private key and all public operation permissions disabled.
    /// Requires RW mode and nonempty ID/label of at most 128 bytes each; rejects
    /// existing public/private IDs. Concurrent writers can race. No private values
    /// are read, no retry/rollback occurs, and failures may leave objects.
    /// Check session closure before releasing results.
    pub fn generate_named_montgomery_key_pair(
        &mut self,
        curve: MontgomeryNamedCurve,
        id: &[u8],
        label: &[u8],
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        crate::montgomery::generate(self, curve.curve(), id, label)
    }

    /// Import checked raw public input as a public, untrusted curveName object
    /// with all operation permissions disabled. Requires RW mode, nonempty
    /// ID/label of at most 128 bytes each and a new public ID. Does not associate
    /// a private key or authenticate ownership. Concurrent writers can race;
    /// native failures may leave objects. Check session closure on every result.
    pub fn import_named_montgomery_public_key(
        &mut self,
        key: &MontgomeryNamedPublicKey,
        id: &[u8],
        label: &[u8],
    ) -> Result<Object<'_, 'm>, Error> {
        crate::montgomery::import_public(self, key.curve.curve(), key.as_bytes(), id, label)
    }
}

impl Session<'_> {
    /// Read bounded raw public metadata requiring exactly the selected curveName
    /// parameters. Rejects RFC 8410 OIDs, other curves and DER-wrapped points.
    pub fn named_montgomery_public_key(
        &mut self,
        key: &ObjectRef,
        curve: MontgomeryNamedCurve,
    ) -> Result<MontgomeryNamedPublicKey, Error> {
        MontgomeryNamedPublicKey::from_bytes(
            curve,
            &crate::montgomery::public_key(self, key, curve.curve())?,
        )
    }

    /// Derive one complete 32/56-byte secret with CKM_ECDH1_DERIVE/CKD_NULL.
    /// Requires RW mode and a matching curveName private key that is private,
    /// sensitive, nonextractable, permits derivation and needs no per-operation
    /// login. The persistent output stays sensitive/nonextractable on the token
    /// and permits further derivation only. Requires a new nonempty secret ID
    /// and label, at most 128 bytes each. Does not authenticate the peer.
    /// No retry/rollback; failures may leave objects. Check session closure.
    /// A raw curve448 secret is 56 bytes and cannot feed the HKDF-SHA512 profile
    /// requiring a 64-byte secret-key input.
    pub fn derive_named_montgomery_secret(
        &mut self,
        base: &ObjectRef,
        peer: &MontgomeryNamedPublicKey,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        validate_secret_identity(id, label)?;
        crate::montgomery::derive(
            self,
            base,
            crate::montgomery::Derivation {
                curve: peer.curve.curve(),
                peer: peer.as_bytes(),
                kdf: EcKdf::null(),
                id,
                label,
                length: peer.as_bytes().len(),
                aes: false,
            },
        )
    }
}
