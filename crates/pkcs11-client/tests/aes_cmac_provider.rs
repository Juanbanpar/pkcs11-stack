// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native AES-CMAC through typed client selectors.
use pkcs11_client::{
    AesCmacProfile, AesKeyPurpose, AesKeyRequest, AesKeySize, Authentication, Error, ErrorKind,
    MacOperation, MechanismType, ObjectRef, Pin, Provider, SessionMode,
};
use secrecy::SecretString;
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn client_cmac_generation_verification_policy_and_reusable_mismatches() {
    let kdf_lane = std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref() == Ok("1");
    assert!(kdf_lane || std::env::var("PKCS11_TEST_ISOLATED").as_deref() == Ok("1"));
    let token_label = if kdf_lane { "kdf-test" } else { "client-test" };
    let provider = Provider::load(
        std::env::var_os(if kdf_lane {
            "PKCS11_TEST_KDF_MODULE"
        } else {
            "PKCS11_TEST_MODULE"
        })
        .unwrap(),
    )
    .unwrap();
    let token = format!("pkcs11:token={token_label}").parse().unwrap();
    let general_supported = provider
        .mechanisms(&token)
        .unwrap()
        .iter()
        .any(|m| m.mechanism == MechanismType::AES_CMAC_GENERAL);
    if kdf_lane {
        assert!(
            general_supported,
            "Kryoptic lane requires native general CMAC"
        );
    }
    let pin = SecretString::from("12345678");
    let mut setup = provider
        .management(
            &token,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    for size in [
        AesKeySize::Bits128,
        AesKeySize::Bits192,
        AesKeySize::Bits256,
    ] {
        assert_eq!(
            provider
                .generation_capabilities(&token)
                .unwrap()
                .aes_cmac_general
                .contains(&size),
            general_supported
        );
        for purpose in [
            AesKeyPurpose::Authentication,
            AesKeyPurpose::AuthenticationGeneral,
        ]
        .into_iter()
        .filter(|purpose| *purpose != AesKeyPurpose::AuthenticationGeneral || general_supported)
        {
            let general = purpose == AesKeyPurpose::AuthenticationGeneral;
            let label = format!("client-cmac-{}-{general}", size.length());
            let request = AesKeyRequest {
                size,
                purpose,
                id: label.as_bytes(),
                label: label.as_bytes(),
            };
            setup.generate_aes_key(&request).unwrap();
            let key = ObjectRef::new(
                format!("pkcs11:token={token_label};object={label};type=secret-key")
                    .parse()
                    .unwrap(),
            )
            .unwrap();
            assert!(setup.export_public(&key).is_err());
            let mut ro = provider
                .management(&token, SessionMode::ReadOnly, Authentication::None)
                .unwrap();
            assert_eq!(
                ro.generate_aes_key(&request).unwrap_err().kind(),
                ErrorKind::Policy
            );
            for op in [MacOperation::Generate, MacOperation::Verify] {
                let options = ro.aes_cmac_options(&key, op).unwrap();
                assert_eq!(options.key_size, size);
                assert_eq!((options.full, options.general), (!general, general));
                assert_eq!(ro.aes_cmac_capabilities(&key, op).is_ok(), !general);
            }
            assert!(
                ro.aes_gcm_capabilities(&key, pkcs11_client::AesGcmOperation::Encrypt)
                    .is_err()
            );
            assert!(
                ro.aes_key_wrap_options(&key, pkcs11_client::KeyOperation::Wrap)
                    .is_err()
            );
            let profiles = if general {
                AesCmacProfile::ALL[1..].to_vec()
            } else {
                vec![AesCmacProfile::Full]
            };
            for profile in profiles {
                for message in [&[][..], b"client MAC message"] {
                    let tag = if general {
                        ro.mac_aes_cmac_with_profile(&key, message, profile)
                            .unwrap()
                    } else {
                        ro.mac_aes_cmac(&key, message).unwrap().to_vec()
                    };
                    ro.verify_aes_cmac_with_profile(&key, message, &tag, profile)
                        .unwrap();
                    let mut changed = tag.clone();
                    changed[profile.tag_length() - 1] ^= 1;
                    for tag in [&[][..], changed.as_slice(), &[0; 17][..]] {
                        assert!(matches!(
                            ro.verify_aes_cmac_with_profile(&key, message, tag, profile),
                            Err(Error::MacMismatch)
                        ));
                        ro.state().unwrap();
                    }
                    assert!(matches!(
                        ro.verify_aes_cmac_with_profile(&key, b"altered", &tag, profile),
                        Err(Error::MacMismatch)
                    ));
                    ro.verify_aes_cmac_with_profile(&key, message, &tag, profile)
                        .unwrap();
                }
            }
            let invalid = AesCmacProfile::General { tag_length: 7 };
            assert_eq!(
                ro.mac_aes_cmac_with_profile(&key, b"message", invalid)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Input
            );
            ro.state().unwrap();
            ro.close().unwrap();
            setup.delete(&key).unwrap();
        }
    }
    setup.close().unwrap();
    provider.finalize().unwrap();
}
