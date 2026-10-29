// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, Object, ObjectRef, Session, Token, key_operations::validate_secret_identity};
use cryptoki::mechanism::elliptic_curve::EcKdf;
use curve25519_dalek::montgomery::MontgomeryPoint;

/// Persistent RFC 8410 X25519 pair with a protected derivation-only private key.
pub struct X25519KeyPairRequest<'a> {
    /// Shared nonempty key ID, at most 128 bytes.
    pub id: &'a [u8],
    /// Shared nonempty label, at most 128 bytes.
    pub label: &'a [u8],
}
impl X25519KeyPairRequest<'_> {
    /// Check identity bounds without provider access.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)
    }
}
impl std::fmt::Debug for X25519KeyPairRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X25519KeyPairRequest([REDACTED])")
    }
}

/// RFC 7748 public input checked for exact length and noncontributory points.
/// Contains public bytes only; it does not authenticate a peer. High-bit and
/// noncanonical field encodings follow RFC 7748 and are preserved for the token.
#[derive(Clone, PartialEq, Eq)]
pub struct X25519PublicKey([u8; 32]);
impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X25519PublicKey([REDACTED])")
    }
}
impl X25519PublicKey {
    /// Validate public input without using a token or any private key. Reject
    /// points which produce all-zero output with a clamped scalar, including
    /// their RFC 7748 encoding aliases. No agreement secret is computed here.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let raw: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKeyOutput)?;
        // The fixed, public probe scalar becomes 2^254 after clamping. On either
        // the curve or its twist it annihilates exactly the small-order points.
        if MontgomeryPoint(raw).mul_clamped([0; 32]).to_bytes() == [0; 32] {
            return Err(Error::InvalidKeyOutput);
        }
        Ok(Self(raw))
    }
    /// Original little-endian public input, without ASN.1 wrapping.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive a complete 32-byte X25519 secret using CKD_NULL. The persistent output
/// is private, sensitive, nonextractable and permits further derivation only.
pub struct X25519Derivation<'a> {
    /// Length-checked, noncontributory-input-checked peer key.
    pub peer: &'a X25519PublicKey,
    /// Nonempty new secret ID, at most 128 bytes; existing IDs are rejected.
    pub id: &'a [u8],
    /// Nonempty label, at most 128 bytes.
    pub label: &'a [u8],
}
impl X25519Derivation<'_> {
    /// Validate output identity bounds without provider calls.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)
    }
}
impl std::fmt::Debug for X25519Derivation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X25519Derivation([REDACTED])")
    }
}

impl Token<'_> {
    /// Advertised Montgomery pair generation with a native entry point, the
    /// generation flag and bounds including 255 field bits. Advisory only:
    /// template acceptance and subsequent agreement support are checked on use.
    pub fn x25519_generation_supported(&self) -> Result<bool, Error> {
        crate::montgomery::generation_supported(self, crate::montgomery::Curve::X25519)
    }
}

impl<'m> Session<'m> {
    /// Generate one persistent RFC 8410 X25519 pair in RW mode. The private key
    /// is sensitive/nonextractable, permits ECDH derivation only and requires no
    /// per-operation login. Checks both public/private IDs before generation;
    /// concurrent writers can race. No retry/rollback; failures may leave objects.
    /// No private values are read. Check session closure before releasing results.
    pub fn generate_x25519_key_pair(
        &mut self,
        request: &X25519KeyPairRequest<'_>,
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        crate::montgomery::generate(
            self,
            crate::montgomery::Curve::X25519,
            request.id,
            request.label,
        )
    }

    /// Import checked raw public input as a public, untrusted RFC 8410 X25519
    /// object, with all operation permissions disabled. Requires RW mode and
    /// bounded nonempty identity; rejects existing public IDs. Does not associate
    /// a private key or authenticate ownership. Concurrent writers can race.
    /// No retry/rollback; native failures may leave objects. Check session closure.
    pub fn import_x25519_public_key(
        &mut self,
        key: &X25519PublicKey,
        id: &[u8],
        label: &[u8],
    ) -> Result<Object<'_, 'm>, Error> {
        crate::montgomery::import_public(
            self,
            crate::montgomery::Curve::X25519,
            key.as_bytes(),
            id,
            label,
        )
    }
}

impl Session<'_> {
    /// Read an RFC 8410 id-X25519 public key. Requires CKK_EC_MONTGOMERY and
    /// OID-form CKA_EC_PARAMS; curveName, Edwards keys, X448 and DER-wrapped points
    /// are outside this profile. Metadata and identity reads are bounded.
    pub fn x25519_public_key(&mut self, key: &ObjectRef) -> Result<X25519PublicKey, Error> {
        X25519PublicKey::from_bytes(&crate::montgomery::public_key(
            self,
            key,
            crate::montgomery::Curve::X25519,
        )?)
    }
    /// Derive once with CKM_ECDH1_DERIVE/CKD_NULL from an existing RFC 8410
    /// id-X25519 private key. Requires RW mode, sensitive/nonextractable private
    /// storage, derivation permission, no always-authenticate requirement and an
    /// allowed mechanism. The complete raw result stays on the token for HKDF.
    /// No fallback or retry occurs; failures may leave persistent objects.
    /// This does not authenticate the peer. Check session closure on every result.
    pub fn derive_x25519_secret(
        &mut self,
        base: &ObjectRef,
        request: &X25519Derivation<'_>,
    ) -> Result<(), Error> {
        request.validate()?;
        crate::montgomery::derive(
            self,
            base,
            crate::montgomery::Derivation {
                curve: crate::montgomery::Curve::X25519,
                peer: request.peer.as_bytes(),
                kdf: EcKdf::null(),
                id: request.id,
                label: request.label,
                length: 32,
                aes: false,
            },
        )
    }
}
