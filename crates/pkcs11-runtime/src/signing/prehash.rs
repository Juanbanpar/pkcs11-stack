// SPDX-License-Identifier: MIT OR Apache-2.0
//! SHA-2/SHA-3/SHAKE support token-hashed messages. Caller digests are limited
//! to SHA-2 because the binding has no standalone SHA-3/SHAKE digest mechanism.

use crate::{Error, MechanismType};

/// Fixed-output or SHAKE prehash algorithm for HashML-DSA/HashSLH-DSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrehashAlgorithm {
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// SHAKE128. Token-hashed message profiles only.
    Shake128,
    /// SHAKE256. Token-hashed message profiles only.
    Shake256,
}

impl PrehashAlgorithm {
    /// Fixed-output prehash algorithms; [`Self::mechanism`] identifies those usable
    /// with caller-supplied digests.
    pub const FIXED: [Self; 8] = [
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
    ];
    /// Every supported prehash.
    pub const ALL: [Self; 10] = [
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
        Self::Shake128,
        Self::Shake256,
    ];

    /// Output length in bytes. SHAKE lengths follow FIPS 204/205 prehash profiles.
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha3_256 | Self::Shake128 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 | Self::Shake256 => 64,
        }
    }

    /// Whether this is an extendable-output function.
    pub fn is_xof(self) -> bool {
        matches!(self, Self::Shake128 | Self::Shake256)
    }

    /// Hash mechanism for a caller-supplied digest, if one exists upstream.
    ///
    /// Published `cryptoki` 0.12.1 exposes standalone SHA-2 mechanisms only.
    /// SHA3 and SHAKE are available through the combined message mechanisms.
    pub fn mechanism(self) -> Option<MechanismType> {
        Some(match self {
            Self::Sha224 => MechanismType::SHA224,
            Self::Sha256 => MechanismType::SHA256,
            Self::Sha384 => MechanismType::SHA384,
            Self::Sha512 => MechanismType::SHA512,
            Self::Sha3_224
            | Self::Sha3_256
            | Self::Sha3_384
            | Self::Sha3_512
            | Self::Shake128
            | Self::Shake256 => return None,
        })
    }
}

impl std::fmt::Display for PrehashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Sha3_224 => "sha3-224",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
            Self::Shake128 => "shake128",
            Self::Shake256 => "shake256",
        })
    }
}

/// Original message or caller-provided digest. Debug omits input bytes.
#[derive(Clone, Copy)]
pub enum HashInput<'a> {
    /// Hash the original message on the token.
    Message {
        /// Prehash algorithm selected by the combined mechanism.
        hash: PrehashAlgorithm,
        /// Original message, at most 64 MiB.
        message: &'a [u8],
    },
    /// Supply an already computed SHA-2 digest.
    Digest {
        /// SHA-224, SHA-256, SHA-384 or SHA-512; other algorithms are rejected.
        hash: PrehashAlgorithm,
        /// Exactly `hash.output_len()` bytes.
        bytes: &'a [u8],
    },
}

impl std::fmt::Debug for HashInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashInput")
            .field("hash", &self.hash())
            .field("prehashed", &self.is_prehashed())
            .finish_non_exhaustive()
    }
}

impl<'a> HashInput<'a> {
    /// Selected prehash algorithm.
    pub fn hash(self) -> PrehashAlgorithm {
        match self {
            Self::Message { hash, .. } | Self::Digest { hash, .. } => hash,
        }
    }

    /// Whether the caller supplied a digest.
    pub fn is_prehashed(self) -> bool {
        matches!(self, Self::Digest { .. })
    }

    /// Borrow the input bytes.
    pub fn bytes(self) -> &'a [u8] {
        match self {
            Self::Message { message, .. } => message,
            Self::Digest { bytes, .. } => bytes,
        }
    }

    pub(super) fn validate(self) -> Result<(), Error> {
        if let Self::Digest { hash, bytes } = self
            && (hash.mechanism().is_none() || bytes.len() != hash.output_len())
        {
            return Err(Error::InvalidParameters(
                "prehash digest length or unsupported prehash",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prehash_lengths_and_xof_boundaries_are_explicit() {
        for (hash, length, xof) in [
            (PrehashAlgorithm::Sha224, 28, false),
            (PrehashAlgorithm::Sha256, 32, false),
            (PrehashAlgorithm::Sha384, 48, false),
            (PrehashAlgorithm::Sha512, 64, false),
            (PrehashAlgorithm::Sha3_224, 28, false),
            (PrehashAlgorithm::Sha3_256, 32, false),
            (PrehashAlgorithm::Sha3_384, 48, false),
            (PrehashAlgorithm::Sha3_512, 64, false),
            (PrehashAlgorithm::Shake128, 32, true),
            (PrehashAlgorithm::Shake256, 64, true),
        ] {
            assert_eq!(hash.output_len(), length);
            assert_eq!(hash.is_xof(), xof);
            assert_eq!(
                hash.mechanism().is_some(),
                matches!(
                    hash,
                    PrehashAlgorithm::Sha224
                        | PrehashAlgorithm::Sha256
                        | PrehashAlgorithm::Sha384
                        | PrehashAlgorithm::Sha512
                )
            );
        }
    }
}
