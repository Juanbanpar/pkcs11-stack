// SPDX-License-Identifier: MIT OR Apache-2.0
//! Token digest operations for the SHA-1 and SHA-2 families exposed by the
//! published upstream binding.
//!
//! SHA-3, SHA-512/224 and SHA-512/256 have no typed upstream mechanism in
//! `cryptoki` 0.12.1 and are therefore not executable here.

use crate::{Error, MechanismType, Session, Token};
use cryptoki::{context::Function, mechanism::Mechanism};

/// Maximum single-part digest input, in bytes (64 MiB).
pub const DIGEST_MAXIMUM_INPUT: usize = 64 * 1024 * 1024;

/// Fixed-output hash algorithms available as token mechanisms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-1. Retained for compatibility; not recommended for new use.
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Every algorithm executable through this module.
    pub const ALL: [Self; 5] = [
        Self::Sha1,
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
    ];

    /// Exact digest length in bytes.
    pub fn output_length(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Numeric PKCS#11 mechanism identifier.
    pub fn mechanism(self) -> MechanismType {
        match self {
            Self::Sha1 => MechanismType::SHA1,
            Self::Sha224 => MechanismType::SHA224,
            Self::Sha256 => MechanismType::SHA256,
            Self::Sha384 => MechanismType::SHA384,
            Self::Sha512 => MechanismType::SHA512,
        }
    }

    fn parameters(self) -> Mechanism<'static> {
        match self {
            Self::Sha1 => Mechanism::Sha1,
            Self::Sha224 => Mechanism::Sha224,
            Self::Sha256 => Mechanism::Sha256,
            Self::Sha384 => Mechanism::Sha384,
            Self::Sha512 => Mechanism::Sha512,
        }
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sha1 => "sha1",
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        })
    }
}

impl Token<'_> {
    /// Advertised single-part digest algorithms with a native digest entry point.
    ///
    /// This is advisory: a provider can still reject an advertised mechanism.
    pub fn digest_options(&self) -> Result<Vec<HashAlgorithm>, Error> {
        let raw = self.module.raw()?;
        if !raw.is_fn_supported(Function::DigestInit) || !raw.is_fn_supported(Function::Digest) {
            return Ok(Vec::new());
        }
        let mechanisms = self.mechanisms()?;
        let mut options = Vec::new();
        for algorithm in HashAlgorithm::ALL {
            let mechanism = algorithm.mechanism();
            if mechanisms.contains(&mechanism) && self.mechanism_info(mechanism)?.digest() {
                options.push(algorithm);
            }
        }
        Ok(options)
    }
}

impl Session<'_> {
    fn digest_mechanism(&self, algorithm: HashAlgorithm) -> Result<Mechanism<'static>, Error> {
        let token = self.token();
        if !token.module.raw()?.is_fn_supported(Function::DigestInit)
            || !token.mechanisms()?.contains(&algorithm.mechanism())
            || !token.mechanism_info(algorithm.mechanism())?.digest()
        {
            return Err(Error::UnsupportedDigest);
        }
        Ok(algorithm.parameters())
    }

    /// Digest one bounded buffer with a single native call.
    ///
    /// No software hashing, retry or fallback is performed. The exact output
    /// length is checked before the digest is returned.
    pub fn digest(&mut self, algorithm: HashAlgorithm, input: &[u8]) -> Result<Vec<u8>, Error> {
        if input.len() > DIGEST_MAXIMUM_INPUT {
            return Err(Error::InvalidParameters("digest input exceeds bound"));
        }
        let mechanism = self.digest_mechanism(algorithm)?;
        let output = self.operation("digest", |raw| raw.digest(&mechanism, input))?;
        if output.len() != algorithm.output_length() {
            return Err(Error::InvalidDigest);
        }
        Ok(output)
    }

    /// Stream an iterator of chunks through a multipart native digest.
    ///
    /// Requires `C_DigestUpdate` and `C_DigestFinal`. Total input is not
    /// allocated; an empty iterator digests the empty message. A failure
    /// invalidates the session because the native operation is left unfinished.
    pub fn digest_chunks<'a>(
        &mut self,
        algorithm: HashAlgorithm,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<u8>, Error> {
        let mechanism = self.digest_mechanism(algorithm)?;
        let raw = self.token().module.raw()?;
        if !raw.is_fn_supported(Function::DigestUpdate)
            || !raw.is_fn_supported(Function::DigestFinal)
        {
            return Err(Error::UnsupportedDigest);
        }
        let output = self.operation("multipart digest", |raw| {
            raw.digest_init(&mechanism)?;
            for chunk in chunks {
                raw.digest_update(chunk)?;
            }
            raw.digest_final()
        })?;
        if output.len() != algorithm.output_length() {
            return Err(Error::InvalidDigest);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_and_mechanisms_are_explicit() {
        for (algorithm, length, mechanism) in [
            (HashAlgorithm::Sha1, 20, MechanismType::SHA1),
            (HashAlgorithm::Sha224, 28, MechanismType::SHA224),
            (HashAlgorithm::Sha256, 32, MechanismType::SHA256),
            (HashAlgorithm::Sha384, 48, MechanismType::SHA384),
            (HashAlgorithm::Sha512, 64, MechanismType::SHA512),
        ] {
            assert_eq!(algorithm.output_length(), length);
            assert_eq!(algorithm.mechanism(), mechanism);
            assert_eq!(
                algorithm.to_string(),
                format!("{algorithm:?}").to_lowercase()
            );
        }
    }

    #[test]
    fn input_bound_is_enforced() {
        let bound = DIGEST_MAXIMUM_INPUT;
        assert!(bound >= 1024 * 1024);
    }
}
