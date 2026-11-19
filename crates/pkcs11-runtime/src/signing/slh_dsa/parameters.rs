// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::Error;
use cryptoki::object::{ParameterSetType, SlhDsaParameterSetType};

/// FIPS 205 SLH-DSA parameter sets. Mechanism bounds use public-key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlhDsaParameterSet {
    /// SLH-DSA-SHA2-128s.
    Sha2_128S,
    /// SLH-DSA-SHA2-128f.
    Sha2_128F,
    /// SLH-DSA-SHA2-192s.
    Sha2_192S,
    /// SLH-DSA-SHA2-192f.
    Sha2_192F,
    /// SLH-DSA-SHA2-256s.
    Sha2_256S,
    /// SLH-DSA-SHA2-256f.
    Sha2_256F,
    /// SLH-DSA-SHAKE-128s.
    Shake128S,
    /// SLH-DSA-SHAKE-128f.
    Shake128F,
    /// SLH-DSA-SHAKE-192s.
    Shake192S,
    /// SLH-DSA-SHAKE-192f.
    Shake192F,
    /// SLH-DSA-SHAKE-256s.
    Shake256S,
    /// SLH-DSA-SHAKE-256f.
    Shake256F,
}
impl SlhDsaParameterSet {
    /// All twelve standardized parameter sets. Provider support is advisory.
    pub const ALL: [Self; 12] = [
        Self::Sha2_128S,
        Self::Sha2_128F,
        Self::Sha2_192S,
        Self::Sha2_192F,
        Self::Sha2_256S,
        Self::Sha2_256F,
        Self::Shake128S,
        Self::Shake128F,
        Self::Shake192S,
        Self::Shake192F,
        Self::Shake256S,
        Self::Shake256F,
    ];
    /// Raw FIPS 205 public-key length in bytes.
    pub fn public_key_length(self) -> usize {
        match self {
            Self::Sha2_128S => 32,
            Self::Sha2_128F => 32,
            Self::Sha2_192S => 48,
            Self::Sha2_192F => 48,
            Self::Sha2_256S => 64,
            Self::Sha2_256F => 64,
            Self::Shake128S => 32,
            Self::Shake128F => 32,
            Self::Shake192S => 48,
            Self::Shake192F => 48,
            Self::Shake256S => 64,
            Self::Shake256F => 64,
        }
    }
    /// Exact FIPS 205 signature length in bytes.
    pub fn signature_length(self) -> usize {
        match self {
            Self::Sha2_128S => 7856,
            Self::Sha2_128F => 17088,
            Self::Sha2_192S => 16224,
            Self::Sha2_192F => 35664,
            Self::Sha2_256S => 29792,
            Self::Sha2_256F => 49856,
            Self::Shake128S => 7856,
            Self::Shake128F => 17088,
            Self::Shake192S => 16224,
            Self::Shake192F => 35664,
            Self::Shake256S => 29792,
            Self::Shake256F => 49856,
        }
    }
    pub(super) fn attribute(self) -> ParameterSetType {
        match self {
            Self::Sha2_128S => SlhDsaParameterSetType::SHA2_128S,
            Self::Sha2_128F => SlhDsaParameterSetType::SHA2_128F,
            Self::Sha2_192S => SlhDsaParameterSetType::SHA2_192S,
            Self::Sha2_192F => SlhDsaParameterSetType::SHA2_192F,
            Self::Sha2_256S => SlhDsaParameterSetType::SHA2_256S,
            Self::Sha2_256F => SlhDsaParameterSetType::SHA2_256F,
            Self::Shake128S => SlhDsaParameterSetType::SHAKE_128S,
            Self::Shake128F => SlhDsaParameterSetType::SHAKE_128F,
            Self::Shake192S => SlhDsaParameterSetType::SHAKE_192S,
            Self::Shake192F => SlhDsaParameterSetType::SHAKE_192F,
            Self::Shake256S => SlhDsaParameterSetType::SHAKE_256S,
            Self::Shake256F => SlhDsaParameterSetType::SHAKE_256F,
        }
        .into()
    }
    pub(super) fn from_attribute(value: ParameterSetType) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|p| p.attribute() == value)
            .ok_or(Error::UnsupportedSigning("unknown SLH-DSA parameter set"))
    }
}
