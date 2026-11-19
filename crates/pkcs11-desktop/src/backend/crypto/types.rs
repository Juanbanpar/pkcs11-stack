// SPDX-License-Identifier: MIT OR Apache-2.0
use std::path::PathBuf;

use pkcs11_client::{
    EdDsaCurve, HashLocation, MechanismType, MlDsaParameterSet, PrehashAlgorithm,
    SignatureParameters, SlhDsaParameterSet,
};

use super::super::{ResourceId, SecretInput};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoMode {
    Hkdf,
    Encapsulate,
    Decapsulate,
    Derive,
    Wrap,
    Unwrap,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoScope {
    pub module: ResourceId,
    pub token: ResourceId,
    pub object: ResourceId,
    pub mode: CryptoMode,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureProfile {
    Classical(SignatureParameters),
    MlDsa(MlDsaParameterSet),
    EdDsa(EdDsaCurve),
    SlhDsa(SlhDsaParameterSet),
    HashMlDsa {
        parameter_set: MlDsaParameterSet,
        hash: PrehashAlgorithm,
        prehashed: bool,
    },
    HashSlhDsa {
        parameter_set: SlhDsaParameterSet,
        hash: PrehashAlgorithm,
        prehashed: bool,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureOption {
    pub parameters: SignatureProfile,
    pub plan: Option<(MechanismType, HashLocation)>,
}
// Contains a one-shot context credential; never formatted or returned to the UI.
pub struct CryptoJob {
    pub parameters: SignatureProfile,
    pub software_hashing: bool,
    pub domain_context: Vec<u8>,
    pub input: PathBuf,
    pub signature: PathBuf,
    pub context: Option<SecretInput>,
}
