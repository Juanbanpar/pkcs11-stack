// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit native KDFs for the separate RFC 8410 and RFC 7748 key profiles.
use crate::{
    AesKeySize, EcdhKdf, Error, MontgomeryNamedPublicKey, ObjectRef, Session, X448PublicKey,
    X25519PublicKey,
    key_operations::validate_secret_identity,
    montgomery::{self, Curve},
};

/// Protected output of a Montgomery agreement. Private and secret values stay
/// on the token; generic secrets permit derivation only, AES permits encryption
/// and decryption only. All outputs are sensitive and nonextractable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MontgomeryOutput {
    /// Complete 32/56-byte agreement value, with the null KDF and empty context.
    RawSecret,
    /// Explicitly KDF-derived generic secret, from 1 through 4096 bytes.
    /// HKDF input additionally requires a length matching its selected hash.
    DerivationSecret {
        /// Requested length in bytes.
        length: usize,
    },
    /// AES key; requires an explicitly selected SHA-2 KDF.
    Aes(AesKeySize),
}
impl MontgomeryOutput {
    /// Requested output length. Raw output has the curve's full agreement width
    /// and returns `None` (32 bytes for 25519, 56 bytes for 448).
    pub fn length(self) -> Option<usize> {
        match self {
            Self::RawSecret => None,
            Self::DerivationSecret { length } => Some(length),
            Self::Aes(size) => Some(size.length()),
        }
    }
}

/// Bounded native Montgomery derivation parameters, independent of peer encoding.
/// Pass a checked peer to the method for its exact token profile. No conversion,
/// KDF fallback, retry or rollback occurs; failures may leave persistent objects.
#[derive(Clone, Copy)]
pub struct MontgomeryKdfRequest<'a> {
    /// Null, ANSI X9.63 or NIST SP 800-56A with SHA-224/256/384/512.
    pub kdf: EcdhKdf,
    /// Public protocol context, at most 4096 bytes; empty for the null KDF.
    pub shared_info: &'a [u8],
    /// Output purpose and explicit length.
    pub output: MontgomeryOutput,
    /// New nonempty secret ID, at most 128 bytes; duplicate IDs are rejected.
    pub id: &'a [u8],
    /// Nonempty label, at most 128 bytes.
    pub label: &'a [u8],
}
impl MontgomeryKdfRequest<'_> {
    /// Validate bounds and KDF/output compatibility without provider access.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)?;
        self.kdf.parameters(self.shared_info)?;
        if self.shared_info.len() > 4096
            || self
                .output
                .length()
                .is_some_and(|n| !(1..=4096).contains(&n))
            || (self.kdf == EcdhKdf::Null) != (self.output == MontgomeryOutput::RawSecret)
            || (self.kdf == EcdhKdf::Null && !self.shared_info.is_empty())
        {
            return Err(Error::InvalidParameters("Montgomery KDF or output"));
        }
        Ok(())
    }
    fn derive(
        &self,
        session: &mut Session<'_>,
        base: &ObjectRef,
        curve: Curve,
        peer: &[u8],
    ) -> Result<(), Error> {
        self.validate()?;
        montgomery::derive(
            session,
            base,
            montgomery::Derivation {
                curve,
                peer,
                kdf: self.kdf.parameters(self.shared_info)?,
                id: self.id,
                label: self.label,
                length: self.output.length().unwrap_or(peer.len()),
                aes: matches!(self.output, MontgomeryOutput::Aes(_)),
            },
        )
    }
}
impl std::fmt::Debug for MontgomeryKdfRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MontgomeryKdfRequest")
            .field("kdf", &self.kdf)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}
impl Session<'_> {
    /// Derive once from a protected RFC 8410 id-X25519 private key in RW mode,
    /// using explicit KDF/output parameters. Rejects curveName and other curves.
    /// Authenticate peer ownership separately and check session closure.
    pub fn derive_x25519_with_kdf(
        &mut self,
        base: &ObjectRef,
        peer: &X25519PublicKey,
        request: &MontgomeryKdfRequest<'_>,
    ) -> Result<(), Error> {
        request.derive(self, base, Curve::X25519, peer.as_bytes())
    }
    /// Derive once from a protected RFC 8410 id-X448 private key in RW mode,
    /// using explicit KDF/output parameters. Rejects curveName and other curves.
    /// Authenticate peer ownership separately and check session closure.
    pub fn derive_x448_with_kdf(
        &mut self,
        base: &ObjectRef,
        peer: &X448PublicKey,
        request: &MontgomeryKdfRequest<'_>,
    ) -> Result<(), Error> {
        request.derive(self, base, Curve::X448, peer.as_bytes())
    }
    /// Derive once from a protected RFC 7748 curveName private key in RW mode,
    /// using explicit KDF/output parameters. Requires exactly the peer's named
    /// profile; RFC 8410 OID keys are rejected. Authenticate peer ownership
    /// separately and check session closure.
    pub fn derive_named_montgomery_with_kdf(
        &mut self,
        base: &ObjectRef,
        peer: &MontgomeryNamedPublicKey,
        request: &MontgomeryKdfRequest<'_>,
    ) -> Result<(), Error> {
        request.derive(self, base, peer.curve().curve(), peer.as_bytes())
    }
}
