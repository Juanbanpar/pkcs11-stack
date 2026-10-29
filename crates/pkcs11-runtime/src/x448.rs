// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AesKeySize, Error, Object, ObjectRef, Session, Token,
    key_operations::validate_secret_identity,
    montgomery::{self, Curve},
};
use cryptoki::mechanism::elliptic_curve::EcKdf;
use ed448_goldilocks_plus::MontgomeryPoint;

/// Persistent RFC 8410 X448 pair with a protected derivation-only private key.
pub struct X448KeyPairRequest<'a> {
    /// Shared nonempty key ID, at most 128 bytes.
    pub id: &'a [u8],
    /// Shared nonempty label, at most 128 bytes.
    pub label: &'a [u8],
}
impl X448KeyPairRequest<'_> {
    /// Check identity bounds without provider access.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)
    }
}
impl std::fmt::Debug for X448KeyPairRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X448KeyPairRequest([REDACTED])")
    }
}

/// Checked 56-byte RFC 7748 public input. Does not authenticate a peer.
/// Noncanonical field encodings are accepted and preserved; unlike X25519,
/// X448 does not mask the high bit. No private material is used for validation.
#[derive(Clone, PartialEq, Eq)]
pub struct X448PublicKey([u8; 56]);
impl std::fmt::Debug for X448PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X448PublicKey([REDACTED])")
    }
}
impl X448PublicKey {
    /// Check length and reject small-order curve/twist points, including their
    /// noncanonical aliases. Normalization is used for validation only.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let raw = bytes.try_into().map_err(|_| Error::InvalidKeyOutput)?;
        // The library normalizes the public field element before its low-order
        // check; checking the original encoding alone would miss p and p+1.
        if MontgomeryPoint(raw)
            .to_projective()
            .to_affine()
            .is_low_order()
        {
            return Err(Error::InvalidKeyOutput);
        }
        Ok(Self(raw))
    }
    /// Original little-endian public bytes, without ASN.1 wrapping.
    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.0
    }
}
/// Explicit X448 KDF. Provider rejection never selects another profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X448Kdf {
    /// Preserve the complete raw secret; requires raw-secret output and no context.
    Null,
    /// ANSI X9.63 SHA-512: Hash(Z || counter || shared info).
    X963Sha512,
    /// NIST SP 800-56A SHA-512: Hash(counter || Z || shared info).
    Sp80056aSha512,
}
/// Protected output purpose. A raw X448 secret is never silently truncated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X448Output {
    /// Complete 56-byte generic secret, permitting derivation only; null KDF only.
    RawSecret,
    /// 64-byte generic secret for HKDF-SHA512, permitting derivation only.
    /// Requires an explicitly selected SHA-512 KDF.
    DerivationSecret,
    /// AES encryption/decryption key; requires a SHA-512 KDF.
    Aes(AesKeySize),
}
impl X448Output {
    /// Output size in bytes.
    pub fn length(self) -> usize {
        match self {
            Self::RawSecret => 56,
            Self::DerivationSecret => 64,
            Self::Aes(size) => size.length(),
        }
    }
}
/// Bounded RFC 8410 id-X448 agreement. All private/secret values stay on the token.
pub struct X448Derivation<'a> {
    /// Checked peer input; the caller must authenticate ownership.
    pub peer: &'a X448PublicKey,
    /// Explicit null or SHA-512 KDF.
    pub kdf: X448Kdf,
    /// Public protocol context, at most 4096 bytes; empty with the null KDF.
    pub shared_info: &'a [u8],
    /// Output purpose and length.
    pub output: X448Output,
    /// Nonempty new secret ID, at most 128 bytes; existing secret IDs are rejected.
    pub id: &'a [u8],
    /// Nonempty label, at most 128 bytes.
    pub label: &'a [u8],
}
impl std::fmt::Debug for X448Derivation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X448Derivation")
            .field("kdf", &self.kdf)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}
impl X448Derivation<'_> {
    /// Check identity, context bounds and KDF/output compatibility without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)?;
        if self.shared_info.len() > 4096
            || (self.kdf == X448Kdf::Null) != (self.output == X448Output::RawSecret)
            || (self.kdf == X448Kdf::Null && !self.shared_info.is_empty())
        {
            return Err(Error::InvalidParameters("X448 KDF or output"));
        }
        Ok(())
    }
}
impl Session<'_> {
    /// Read bounded public metadata for one RFC 8410 id-X448 Montgomery object.
    /// Requires OID parameters and raw public bytes; curveName and Edwards keys
    /// are rejected. Does not establish trust or private-key association.
    pub fn x448_public_key(&mut self, key: &ObjectRef) -> Result<X448PublicKey, Error> {
        X448PublicKey::from_bytes(&montgomery::public_key(self, key, Curve::X448)?)
    }
    /// Derive once from an existing RFC 8410 X448 private key in RW mode. Requires
    /// sensitive/nonextractable private storage, derivation permission, no context
    /// authentication and native ECDH support with 448-bit bounds. Outputs remain
    /// private, sensitive and nonextractable. Failures may leave persistent objects;
    /// no retry/rollback occurs. Authenticate the peer and check session closure.
    /// Raw 56-byte output cannot feed this application's hash-length HKDF profile;
    /// explicitly choose a SHA-512 KDF and 64-byte output for HKDF-SHA512.
    pub fn derive_x448_key(
        &mut self,
        base: &ObjectRef,
        request: &X448Derivation<'_>,
    ) -> Result<(), Error> {
        request.validate()?;
        let kdf = match request.kdf {
            X448Kdf::Null => EcKdf::null(),
            X448Kdf::X963Sha512 => EcKdf::sha512(request.shared_info),
            X448Kdf::Sp80056aSha512 => EcKdf::sha512_sp800(request.shared_info),
        };
        montgomery::derive(
            self,
            base,
            montgomery::Derivation {
                curve: Curve::X448,
                peer: request.peer.as_bytes(),
                kdf,
                id: request.id,
                label: request.label,
                length: request.output.length(),
                aes: matches!(request.output, X448Output::Aes(_)),
            },
        )
    }
}

impl Token<'_> {
    /// Advertised Montgomery pair generation with a native entry point, the
    /// generation flag and bounds including 448 field bits. Advisory only:
    /// template acceptance and subsequent agreement support are checked on use.
    pub fn x448_generation_supported(&self) -> Result<bool, Error> {
        montgomery::generation_supported(self, Curve::X448)
    }
}

impl<'m> Session<'m> {
    /// Generate one persistent RFC 8410 X448 pair in RW mode. The private key
    /// is sensitive/nonextractable, permits ECDH derivation only and requires no
    /// per-operation login. Checks both public/private IDs before generation;
    /// concurrent writers can race. No retry/rollback; failures may leave objects.
    /// No private values are read. Check session closure before releasing results.
    pub fn generate_x448_key_pair(
        &mut self,
        request: &X448KeyPairRequest<'_>,
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        montgomery::generate(self, Curve::X448, request.id, request.label)
    }

    /// Import checked raw public input as a public, untrusted RFC 8410 X448
    /// object, with all operation permissions disabled. Requires RW mode and
    /// bounded nonempty identity; rejects existing public IDs. Does not associate
    /// a private key or authenticate ownership. Concurrent writers can race.
    /// No retry/rollback; native failures may leave objects. Check session closure.
    pub fn import_x448_public_key(
        &mut self,
        key: &X448PublicKey,
        id: &[u8],
        label: &[u8],
    ) -> Result<Object<'_, 'm>, Error> {
        montgomery::import_public(self, Curve::X448, key.as_bytes(), id, label)
    }
}
