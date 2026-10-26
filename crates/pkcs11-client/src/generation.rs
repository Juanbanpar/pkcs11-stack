// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, KeyKind, ManagementSession, MechanismType, NamedCurve, Pkcs11Uri, Provider};
pub use pkcs11_runtime::{AesKeyPurpose, AesKeyRequest, AesKeySize, EcdhKeyPairRequest};

/// Advisory generation choices shared by frontends. Fields describe generation
/// only: they do not guarantee template acceptance or later operation support.
/// This is not an atomic snapshot; execution rechecks the selected token.
#[derive(Clone, Debug)]
pub struct GenerationCapabilities {
    /// Common RSA sizes and named EC signing curves.
    pub signing: Vec<KeyKind>,
    /// Named curves for derivation-only key-pair templates.
    pub ecdh: Vec<NamedCurve>,
    /// AES sizes for encryption-only or wrapping-only key templates.
    pub aes: Vec<AesKeySize>,
    /// Pure ML-DSA parameter sets.
    pub ml_dsa: Vec<crate::MlDsaParameterSet>,
    /// ML-KEM parameter sets.
    pub ml_kem: Vec<crate::MlKemParameterSet>,
}
impl Provider {
    /// Collect classical, PQC, ECDH and AES generation choices without opening
    /// sessions or generating keys. Unknown/unsupported mechanisms yield empty
    /// choices; provider errors propagate. No mechanism planning belongs in a UI.
    pub fn generation_capabilities(
        &self,
        token: &Pkcs11Uri,
    ) -> Result<GenerationCapabilities, Error> {
        let selected = self.module.resolve_token_uri(token)?;
        Ok(GenerationCapabilities {
            signing: self.generation_options(token)?,
            ecdh: selected.ecdh_generation_options()?,
            aes: selected.aes_generation_options()?,
            ml_dsa: self.ml_dsa_generation_options(token)?,
            ml_kem: self.ml_kem_generation_options(token)?,
        })
    }
}
impl ManagementSession<'_> {
    /// Generate a persistent derivation-only EC pair with a bounded shared ID/label.
    /// Private material is sensitive/nonextractable; no signing or context authentication.
    /// Requires RW mode; existing public/private key IDs are rejected before crypto.
    /// Failures can leave persistent effects. No retry or rollback; check closure.
    pub fn generate_ecdh_key_pair(
        &mut self,
        request: &EcdhKeyPairRequest<'_>,
    ) -> Result<(), Error> {
        self.session.generate_ecdh_key_pair(request)?;
        Ok(())
    }
    /// Generate a persistent private, sensitive, nonextractable AES key. Only the
    /// selected encryption/decryption or wrapping/unwrapping permissions are enabled.
    /// Requires RW mode; duplicate secret IDs are rejected. No key values are read,
    /// no retry/rollback occurs, and failures may leave objects. Check session closure.
    pub fn generate_aes_key(&mut self, request: &AesKeyRequest<'_>) -> Result<(), Error> {
        self.session.generate_aes_key(request)?;
        Ok(())
    }
}

pub(crate) fn choices(
    mechanism: MechanismType,
    generate_pair: bool,
    minimum: usize,
    maximum: usize,
) -> Vec<KeyKind> {
    if !generate_pair {
        return Vec::new();
    }
    if mechanism == MechanismType::RSA_PKCS_KEY_PAIR_GEN {
        [2048, 3072, 4096, 8192, 16384]
            .into_iter()
            .filter(|bits| (minimum..=maximum).contains(bits))
            .map(|bits| KeyKind::Rsa { bits })
            .collect()
    } else if mechanism == MechanismType::ECC_KEY_PAIR_GEN {
        [NamedCurve::P256, NamedCurve::P384, NamedCurve::P521]
            .into_iter()
            .filter(|curve| (minimum..=maximum).contains(&curve.bits()))
            .map(KeyKind::Ec)
            .collect()
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn choices_require_generation_flag_and_respect_bounds() {
        assert!(choices(MechanismType::RSA_PKCS_KEY_PAIR_GEN, false, 0, 16384).is_empty());
        assert!(choices(MechanismType::RSA_PKCS, true, 0, 16384).is_empty());
        assert_eq!(
            choices(MechanismType::RSA_PKCS_KEY_PAIR_GEN, true, 3072, 4096),
            vec![KeyKind::Rsa { bits: 3072 }, KeyKind::Rsa { bits: 4096 }]
        );
        assert_eq!(
            choices(MechanismType::ECC_KEY_PAIR_GEN, true, 384, 521),
            vec![KeyKind::Ec(NamedCurve::P384), KeyKind::Ec(NamedCurve::P521)]
        );
        assert!(choices(MechanismType::ECC_KEY_PAIR_GEN, true, 1024, 0).is_empty());
    }
}
