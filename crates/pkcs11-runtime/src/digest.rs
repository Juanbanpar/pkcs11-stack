// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, Session, Token, error::backend};
use cryptoki::{
    context::Function,
    mechanism::{Mechanism, MechanismType},
};
use std::cell::Cell;

/// Modern fixed-output hash algorithms for standalone token digest operations.
/// These choices are independent of signature hashes and MGF support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA-512/224 (distinct from truncating SHA-512).
    Sha512_224,
    /// SHA-512/256 (distinct from truncating SHA-512).
    Sha512_256,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
}
impl HashAlgorithm {
    /// All modern fixed-output digest choices, without assuming provider support.
    pub const ALL: [Self; 10] = [
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha512_224,
        Self::Sha512_256,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
    ];
    /// Output length in bytes, used to bound native allocations.
    pub fn output_length(self) -> usize {
        match self {
            Self::Sha224 | Self::Sha512_224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha512_256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }
    /// Standard mechanism ID; representability does not imply token support.
    pub fn mechanism(self) -> MechanismType {
        self.parameters().mechanism_type()
    }
    fn parameters(self) -> Mechanism<'static> {
        match self {
            Self::Sha224 => Mechanism::Sha224,
            Self::Sha256 => Mechanism::Sha256,
            Self::Sha384 => Mechanism::Sha384,
            Self::Sha512 => Mechanism::Sha512,
            Self::Sha512_224 => Mechanism::Sha512_224,
            Self::Sha512_256 => Mechanism::Sha512_256,
            Self::Sha3_224 => Mechanism::Sha3_224,
            Self::Sha3_256 => Mechanism::Sha3_256,
            Self::Sha3_384 => Mechanism::Sha3_384,
            Self::Sha3_512 => Mechanism::Sha3_512,
        }
    }
}
impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Sha512_224 => "sha512-224",
            Self::Sha512_256 => "sha512-256",
            Self::Sha3_224 => "sha3-224",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
        })
    }
}
/// Digest entry points required for an advisory capability query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestMode {
    /// C_DigestInit and C_Digest.
    SinglePart,
    /// C_DigestInit, C_DigestUpdate and C_DigestFinal.
    Multipart,
}
impl Token<'_> {
    /// Advertised hash mechanisms with CKF_DIGEST and all required function
    /// pointers. No digest, authentication, software fallback or parameter trial.
    pub fn digest_algorithms(&self, mode: DigestMode) -> Result<Vec<HashAlgorithm>, Error> {
        let raw = self.module.raw()?;
        let functions: &[Function] = match mode {
            DigestMode::SinglePart => &[Function::DigestInit, Function::Digest],
            DigestMode::Multipart => &[
                Function::DigestInit,
                Function::DigestUpdate,
                Function::DigestFinal,
            ],
        };
        if !functions
            .iter()
            .all(|function| raw.is_fn_supported(*function))
        {
            return Ok(vec![]);
        }
        let mechanisms = self.mechanisms()?;
        let mut algorithms = vec![];
        for algorithm in HashAlgorithm::ALL {
            if mechanisms.contains(&algorithm.mechanism())
                && self.mechanism_info(algorithm.mechanism())?.digest()
            {
                algorithms.push(algorithm);
            }
        }
        Ok(algorithms)
    }
}
/// Exclusive multipart digest. Input chunks are never retained. Dropping an
/// unfinished operation or any native error leaves its session unusable; closing
/// the session discards the native operation. Successful finish or an explicit,
/// confirmed cancellation restores reuse.
/// No operation-state export, implicit cancellation, retry or fallback occurs.
pub struct DigestOperation<'a> {
    raw: &'a cryptoki::session::Session,
    healthy: &'a Cell<bool>,
    algorithm: HashAlgorithm,
    active: bool,
    cancellation_supported: bool,
}
impl std::fmt::Debug for DigestOperation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DigestOperation")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}
impl Drop for DigestOperation<'_> {
    fn drop(&mut self) {
        if self.active {
            self.healthy.set(false);
        }
    }
}
impl DigestOperation<'_> {
    /// Process one chunk, including an empty chunk. A failed update prevents
    /// further updates and finalization; the caller must close/discard the session.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        if let Err(error) = self.raw.digest_update(bytes) {
            self.active = false;
            return Err(backend("update digest", error));
        }
        Ok(())
    }
    /// Consume this active guard and cancel only its digest operation once.
    /// Only confirmed native termination restores reuse. Unsupported interfaces,
    /// stubs and other failures leave the session unusable. A failed update cannot
    /// be repaired by cancellation. Drop never cancels implicitly.
    pub fn cancel(mut self) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        crate::cancellation::cancel(
            self.raw,
            self.cancellation_supported,
            crate::CancelFlags::DIGEST,
        )?;
        self.active = false;
        self.healthy.set(true);
        Ok(())
    }
    /// Complete once, returning exactly the selected hash length and restoring
    /// the session only on success. The output allocation is at most 64 bytes.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        if !self.active {
            return Err(Error::Closed);
        }
        let output = self
            .raw
            .digest_final_fixed(self.algorithm.output_length())
            .map_err(|error| backend("finish digest", error))?;
        self.active = false;
        self.healthy.set(true);
        Ok(output)
    }
}
impl Session<'_> {
    fn check_digest(&self, algorithm: HashAlgorithm, mode: DigestMode) -> Result<(), Error> {
        self.validate()?;
        if !self.token().digest_algorithms(mode)?.contains(&algorithm) {
            return Err(Error::UnsupportedDigest);
        }
        Ok(())
    }
    /// Hash one message on the token, without a key or software fallback. The
    /// caller supplies ordinary login if the provider requires it. Native failure
    /// discards the session; output allocation is bounded by the selected hash.
    pub fn digest(&mut self, algorithm: HashAlgorithm, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        self.check_digest(algorithm, DigestMode::SinglePart)?;
        let raw = self.raw()?;
        self.healthy.set(false);
        raw.digest_init(&algorithm.parameters())
            .map_err(|e| backend("initialize digest", e))?;
        let output = raw
            .digest_initialized_fixed(bytes, algorithm.output_length())
            .map_err(|e| backend("digest", e))?;
        self.healthy.set(true);
        Ok(output)
    }
    /// Begin an exclusive multipart digest. Abandoning this guard makes the
    /// session unusable even when no chunks were processed. No keys are accepted.
    pub fn start_digest(&mut self, algorithm: HashAlgorithm) -> Result<DigestOperation<'_>, Error> {
        self.check_digest(algorithm, DigestMode::Multipart)?;
        let raw = self.raw()?;
        self.healthy.set(false);
        raw.digest_init(&algorithm.parameters())
            .map_err(|e| backend("initialize digest", e))?;
        Ok(DigestOperation {
            raw,
            healthy: &self.healthy,
            algorithm,
            active: true,
            cancellation_supported: self
                .token()
                .module
                .supports_function(Function::SessionCancel),
        })
    }
}
