// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{KeyKind, MechanismType, NamedCurve};

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
