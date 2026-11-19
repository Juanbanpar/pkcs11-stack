// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{KeyKind, MechanismType};
use cryptoki::mechanism::rsa::PkcsMgfType;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

/// Supported message digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-1. Disabled by default; legacy opt-in only.
    Sha1,
    /// SHA-224. Disabled by default; opt in through an explicit policy.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}
impl DigestAlgorithm {
    /// Digest length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
    pub(super) fn mechanism(self) -> MechanismType {
        match self {
            Self::Sha1 => MechanismType::SHA1,
            Self::Sha224 => MechanismType::SHA224,
            Self::Sha256 => MechanismType::SHA256,
            Self::Sha384 => MechanismType::SHA384,
            Self::Sha512 => MechanismType::SHA512,
        }
    }
    pub(super) fn mgf(self) -> PkcsMgfType {
        match self {
            Self::Sha1 => PkcsMgfType::MGF1_SHA1,
            Self::Sha224 => PkcsMgfType::MGF1_SHA224,
            Self::Sha256 => PkcsMgfType::MGF1_SHA256,
            Self::Sha384 => PkcsMgfType::MGF1_SHA384,
            Self::Sha512 => PkcsMgfType::MGF1_SHA512,
        }
    }
    pub(super) fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha224 => Sha224::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}
/// Generic signature family, independent of protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5, with a DER DigestInfo for the selected digest.
    RsaPkcs1,
    /// RSASSA-PSS, requiring explicit MGF1 digest and salt length.
    RsaPss,
    /// ECDSA, returned as fixed-width PKCS#11 r || s.
    Ecdsa,
}
/// Explicit PSS parameters. No default salt or MGF is inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PssParameters {
    /// Digest used by MGF1; independent of the message digest.
    pub mgf_digest: DigestAlgorithm,
    /// Exact salt size in bytes.
    pub salt_len: usize,
}
/// Debug omits input bytes.
#[derive(Clone, Copy)]
pub enum SignInput<'a> {
    /// Unhashed message.
    Message(&'a [u8]),
    /// Precomputed digest of exactly the selected digest length.
    Digest(&'a [u8]),
}
impl std::fmt::Debug for SignInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Message(_) => "Message([REDACTED])",
            Self::Digest(_) => "Digest([REDACTED])",
        })
    }
}
/// A signing request, with no protocol-specific encodings.
#[derive(Debug, Clone, Copy)]
pub struct SignRequest<'a> {
    /// Signature family.
    pub algorithm: SignatureAlgorithm,
    /// Message digest algorithm, also identifying a supplied digest.
    pub digest: DigestAlgorithm,
    /// Message or digest; these are never interchangeable.
    pub input: SignInput<'a>,
    /// Required for PSS and forbidden for other algorithms.
    pub pss: Option<PssParameters>,
}

/// Mechanism advertisement, including signing flags and key-size bounds in bits.
#[derive(Debug, Clone)]
pub struct SigningMechanism {
    /// PKCS#11 mechanism identifier.
    pub mechanism: MechanismType,
    /// CKF_SIGN is present.
    pub can_sign: bool,
    /// Minimum supported RSA/EC key size in bits.
    pub minimum_bits: usize,
    /// Maximum supported RSA/EC key size in bits.
    pub maximum_bits: usize,
}
/// An inspectable capability snapshot. Signing always rediscovers it in the live session.
#[derive(Debug, Clone)]
pub struct KeyCapabilities {
    /// Key type and public size/curve.
    pub key: KeyKind,
    /// CKA_SIGN.
    pub can_sign: bool,
    /// CKA_ALWAYS_AUTHENTICATE.
    pub always_authenticate: bool,
    /// None means the attribute is unsupported; an empty list means unrestricted.
    pub allowed_mechanisms: Option<Vec<MechanismType>>,
    /// Actual token mechanism information.
    pub mechanisms: Vec<SigningMechanism>,
}
