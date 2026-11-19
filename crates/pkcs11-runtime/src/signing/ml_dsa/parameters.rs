// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::Error;
use cryptoki::object::{MlDsaParameterSetType, ParameterSetType};

/// FIPS 204 parameter sets. Mechanism key-size bounds use public-key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsaParameterSet {
    /// ML-DSA-44 (NIST security category 2).
    MlDsa44,
    /// ML-DSA-65 (NIST security category 3).
    MlDsa65,
    /// ML-DSA-87 (NIST security category 5).
    MlDsa87,
}
impl MlDsaParameterSet {
    /// Exact encoded public-key length, in bytes.
    pub fn public_key_length(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }
    /// Exact signature length, in bytes.
    pub fn signature_length(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
    pub(super) fn attribute(self) -> ParameterSetType {
        match self {
            Self::MlDsa44 => MlDsaParameterSetType::ML_DSA_44,
            Self::MlDsa65 => MlDsaParameterSetType::ML_DSA_65,
            Self::MlDsa87 => MlDsaParameterSetType::ML_DSA_87,
        }
        .into()
    }
    pub(super) fn from_attribute(value: ParameterSetType) -> Result<Self, Error> {
        [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87]
            .into_iter()
            .find(|parameter| parameter.attribute() == value)
            .ok_or(Error::UnsupportedSigning("unknown ML-DSA parameter set"))
    }
}
