// SPDX-License-Identifier: MIT OR Apache-2.0
//! Mechanism metadata must preserve identifiers independently of typed execution support.
use pkcs11_runtime::MechanismType;

#[test]
fn hkdf_parameters_represent_individual_stages_without_null_slice_reads() {
    use cryptoki::mechanism::hkdf::{HkdfParams, HkdfSalt};
    let salt = [1, 2, 3];
    let extract = HkdfParams::new(MechanismType::SHA256, Some(HkdfSalt::Data(&salt)), None);
    assert!(extract.extract());
    assert!(!extract.expand());
    assert!(extract.info().is_empty());
    assert!(matches!(extract.salt(), HkdfSalt::Data(bytes) if bytes == salt));
    let expand = HkdfParams::new(MechanismType::SHA256, None, Some(&[]));
    assert!(!expand.extract());
    assert!(expand.expand());
    assert!(expand.info().is_empty());
}

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

#[test]
fn hmac_key_types_preserve_distinct_standard_ids() {
    use pkcs11_runtime::KeyType;
    for (key_type, raw) in [
        (KeyType::SHA256_HMAC, 0x2B),
        (KeyType::SHA384_HMAC, 0x2C),
        (KeyType::SHA512_HMAC, 0x2D),
        (KeyType::SHA224_HMAC, 0x2E),
        (KeyType::SHA512_224_HMAC, 0x43),
        (KeyType::SHA512_256_HMAC, 0x44),
        (KeyType::SHA3_224_HMAC, 0x36),
        (KeyType::SHA3_256_HMAC, 0x37),
        (KeyType::SHA3_384_HMAC, 0x38),
        (KeyType::SHA3_512_HMAC, 0x39),
    ] {
        assert_eq!(*key_type, raw);
        assert_eq!(KeyType::try_from(raw).unwrap(), key_type);
    }
}

#[test]
fn newer_metadata_attribute_ids_round_trip() {
    use pkcs11_runtime::AttributeType;
    for (kind, raw) in [
        (AttributeType::UniqueId, 0x0004),
        (AttributeType::PublicKeyInfo, 0x0129),
        (AttributeType::ProfileId, 0x0601),
        (AttributeType::ObjectValidationFlags, 0x061E),
        (AttributeType::ValidationType, 0x061F),
        (AttributeType::ValidationVersion, 0x0620),
        (AttributeType::ValidationLevel, 0x0621),
        (AttributeType::ValidationModuleId, 0x0622),
        (AttributeType::ValidationFlag, 0x0623),
        (AttributeType::ValidationAuthorityType, 0x0624),
        (AttributeType::ValidationCountry, 0x0625),
        (AttributeType::ValidationCertificateIdentifier, 0x0626),
        (AttributeType::ValidationCertificateUri, 0x0627),
        (AttributeType::ValidationVendorUri, 0x0628),
        (AttributeType::ValidationProfile, 0x0629),
    ] {
        assert_eq!(*cryptoki::types::Ulong::new(kind.into()), raw);
        assert_eq!(AttributeType::try_from(raw).unwrap(), kind);
    }
}

#[test]
fn opaque_metadata_ids_survive_construction_and_numeric_display() {
    use cryptoki::{
        object::{
            CertificateType, KeyType, ObjectClass, ProfileIdType, ValidationAuthorityType,
            ValidationType,
        },
        types::Ulong,
    };
    for raw in [0x7fff_0001, 0x8000_0001, *Ulong::new(!0)] {
        let class = ObjectClass::try_from(raw).unwrap();
        let key = KeyType::try_from(raw).unwrap();
        let certificate = CertificateType::try_from(raw).unwrap();
        let profile = ProfileIdType::try_from(raw).unwrap();
        let validation = ValidationType::try_from(raw).unwrap();
        let authority = ValidationAuthorityType::try_from(raw).unwrap();
        assert_eq!(*class, raw);
        assert_eq!(*key, raw);
        assert_eq!(*certificate, raw);
        assert_eq!(*profile.as_ref(), raw);
        assert_eq!(*validation, raw);
        assert_eq!(*authority, raw);
        for display in [
            class.to_string(),
            key.to_string(),
            certificate.to_string(),
            profile.to_string(),
            validation.to_string(),
            authority.to_string(),
        ] {
            assert!(display.contains(&format!("{raw:08x}")), "{display}");
        }
    }
    assert!(KeyType::new_vendor_defined(0x7fff_0001).is_err());
    assert_eq!(
        *ObjectClass::try_from(*ObjectClass::PRIVATE_KEY).unwrap(),
        *ObjectClass::PRIVATE_KEY
    );
    assert_eq!(
        KeyType::try_from(*KeyType::RSA).unwrap().to_string(),
        "CKK_RSA"
    );
    assert_eq!(
        CertificateType::try_from(*CertificateType::X_509)
            .unwrap()
            .to_string(),
        "CKC_X_509"
    );
}
