// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, KeyKind, ManagementSession, MechanismType, NamedCurve, Pkcs11Uri, Provider};
pub use pkcs11_runtime::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, EcdhKeyPairRequest, RsaEncryptionKeyPairRequest,
};

/// Advisory generation choices shared by frontends. Fields describe generation
/// only: they do not guarantee template acceptance or later operation support.
/// This is not an atomic snapshot; execution rechecks the selected token.
#[derive(Clone, Debug)]
pub struct GenerationCapabilities {
    /// Common RSA sizes and named EC signing curves.
    pub signing: Vec<KeyKind>,
    /// Common RSA encryption/decryption-only pair sizes, in bits.
    pub rsa_encryption: Vec<usize>,
    /// Named curves for derivation-only key-pair templates.
    pub ecdh: Vec<NamedCurve>,
    /// RFC 8410 X25519 pair generation, independent of agreement support.
    pub x25519: bool,
    /// RFC 8410 X448 pair generation, independent of agreement support.
    pub x448: bool,
    /// RFC 7748 curveName generation choices; template acceptance is advisory.
    pub montgomery_named: Vec<crate::MontgomeryNamedCurve>,
    /// AES sizes for encryption, wrapping or CMAC authentication key templates.
    pub aes: Vec<AesKeySize>,
    /// AES sizes with native general-CMAC support for authentication-only templates.
    pub aes_cmac_general: Vec<AesKeySize>,
    /// Algorithms for hash-length HMAC-only generic secret generation.
    pub hmac: Vec<crate::HmacAlgorithm>,
    /// Algorithms for secrets restricted to native general HMAC mechanisms.
    pub hmac_general: Vec<crate::HmacAlgorithm>,
    /// Pure Ed25519 and Ed448 signing curves.
    pub eddsa: Vec<crate::EdDsaCurve>,
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
        let mut montgomery_named = Vec::new();
        for curve in [
            crate::MontgomeryNamedCurve::Curve25519,
            crate::MontgomeryNamedCurve::Curve448,
        ] {
            if selected.named_montgomery_generation_supported(curve)? {
                montgomery_named.push(curve);
            }
        }
        Ok(GenerationCapabilities {
            signing: self.generation_options(token)?,
            rsa_encryption: selected.rsa_encryption_generation_options()?,
            ecdh: selected.ecdh_generation_options()?,
            x25519: selected.x25519_generation_supported()?,
            x448: selected.x448_generation_supported()?,
            montgomery_named,
            aes: selected.aes_generation_options()?,
            aes_cmac_general: selected.aes_cmac_general_generation_options()?,
            hmac: selected.hmac_generation_options()?,
            hmac_general: selected.hmac_general_generation_options()?,
            eddsa: selected.eddsa_generation_options()?,
            ml_dsa: self.ml_dsa_generation_options(token)?,
            ml_kem: self.ml_kem_generation_options(token)?,
        })
    }
}
impl ManagementSession<'_> {
    /// Generate a persistent encryption-only RSA pair with a bounded shared ID
    /// and label, sensitive/nonextractable private key and optional context auth.
    /// Requires RW access. Capabilities and duplicate IDs are checked before crypto;
    /// failure can leave objects and no retry/rollback is performed.
    pub fn generate_rsa_encryption_key_pair(
        &mut self,
        request: &RsaEncryptionKeyPairRequest<'_>,
    ) -> Result<(), Error> {
        self.session.generate_rsa_encryption_key_pair(request)?;
        Ok(())
    }
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
    /// selected encryption, wrapping or CMAC authentication permissions are enabled.
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
