// SPDX-License-Identifier: MIT OR Apache-2.0
//! Mechanism metadata must preserve identifiers independently of typed execution support.
use pkcs11_runtime::MechanismType;

#[test]
fn aes_kwp_has_the_standard_identifier_and_is_distinct_from_deprecated_pad() {
    let mechanism = cryptoki::mechanism::Mechanism::AesKeyWrapKwp;
    assert_eq!(*mechanism.mechanism_type(), 0x210B);
    assert_ne!(mechanism.mechanism_type(), MechanismType::AES_KEY_WRAP_PAD);
    assert_eq!(
        mechanism.mechanism_type().to_string(),
        "CKM_AES_KEY_WRAP_KWP"
    );
}

#[test]
fn standard_unknown_and_vendor_mechanism_ids_round_trip() {
    for raw in [
        0x0000_1087, // CKM_AES_GCM, already supported by the binding.
        0x0000_1088, // CKM_AES_CCM.
        0x0000_108b, // CKM_AES_CMAC_GENERAL.
        0x0000_02b0, // CKM_SHA3_256.
        0x0000_002c, // CKM_HASH_ML_DSA_SHAKE256.
        0x7fff_0001, // Unknown standard-range identifier.
        0x8000_0001, // Vendor-defined identifier.
        !0,
    ] {
        let mechanism = MechanismType::try_from(raw).unwrap();
        assert_eq!(*mechanism, raw);
    }
}
