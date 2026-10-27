// SPDX-License-Identifier: MIT OR Apache-2.0
//! Full/general CMAC against independent OpenSSL, including restrictive key policy.
use pkcs11_runtime::{
    AesCmacProfile, AesKeyPurpose, AesKeyRequest, AesKeySize, Attribute, AttributeType,
    Authentication, Error, KeyType, MacOperation, MechanismType, Module, ObjectClass, ObjectRef,
    Pin, SessionMode,
};
use secrecy::SecretString;
use std::{
    io::Write,
    process::{Command, Stdio},
};
fn kdf_lane() -> bool {
    std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref() == Ok("1")
}
fn token_label() -> &'static str {
    if kdf_lane() {
        "kdf-test"
    } else {
        "client-test"
    }
}
fn reference(label: &str) -> ObjectRef {
    ObjectRef::new(
        format!(
            "pkcs11:token={};object={label};type=secret-key",
            token_label()
        )
        .parse()
        .unwrap(),
    )
    .unwrap()
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn aes_cmac_independent_tags_permissions_generation_and_reuse() {
    assert!(kdf_lane() || std::env::var("PKCS11_TEST_ISOLATED").as_deref() == Ok("1"));
    let module = Module::load(
        std::env::var_os(if kdf_lane() {
            "PKCS11_TEST_KDF_MODULE"
        } else {
            "PKCS11_TEST_MODULE"
        })
        .unwrap(),
    )
    .unwrap();
    let token = module
        .resolve_token_uri(&format!("pkcs11:token={}", token_label()).parse().unwrap())
        .unwrap();
    let general_supported = token
        .mechanisms()
        .unwrap()
        .contains(&MechanismType::AES_CMAC_GENERAL);
    if kdf_lane() {
        assert!(
            general_supported,
            "Kryoptic lane requires native general CMAC"
        );
    }
    let pin = SecretString::from("12345678");
    let mut setup = token.open_session(SessionMode::ReadWrite).unwrap();
    setup
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for size in [
        AesKeySize::Bits128,
        AesKeySize::Bits192,
        AesKeySize::Bits256,
    ] {
        assert_eq!(
            token
                .aes_cmac_general_generation_options()
                .unwrap()
                .contains(&size),
            general_supported
        );
        if !general_supported {
            assert!(matches!(
                setup.generate_aes_key(&AesKeyRequest {
                    size,
                    purpose: AesKeyPurpose::AuthenticationGeneral,
                    id: b"unsupported-general",
                    label: b"unsupported general"
                }),
                Err(Error::UnsupportedKeyOperation)
            ));
            setup.info().unwrap();
        }
        let label = format!("cmac-vector-{}", size.length() * 8);
        let value = vec![0x42; size.length()];
        let base = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Verify(true),
            Attribute::Id(label.as_bytes().to_vec()),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Value(value.clone()),
        ];
        setup.create_object(&base).unwrap();
        let key = reference(&label);
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        for length in [0, 1, 16, 40, 64, 4097] {
            let message = vec![0xA5; length];
            let mut command = Command::new("openssl")
                .args([
                    "mac",
                    "-macopt",
                    &format!("cipher:AES-{}-CBC", size.length() * 8),
                    "-macopt",
                    &format!("hexkey:{}", "42".repeat(size.length())),
                    "-binary",
                    "CMAC",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            command.stdin.take().unwrap().write_all(&message).unwrap();
            let expected = command.wait_with_output().unwrap();
            assert!(expected.status.success());
            let tag = session.mac_aes_cmac(&key, &message).unwrap();
            assert_eq!(tag.as_slice(), expected.stdout);
            // Disposable vectors exercise all lengths; protocols fix one length per key.
            let options = session
                .aes_cmac_options(&key, MacOperation::Generate)
                .unwrap();
            assert!(options.full);
            assert_eq!(options.general, general_supported);
            for tag_length in (8..=16).filter(|_| general_supported) {
                let profile = AesCmacProfile::General { tag_length };
                let tag = session
                    .mac_aes_cmac_with_profile(&key, &message, profile)
                    .unwrap();
                assert_eq!(tag, expected.stdout[..tag_length]);
                session
                    .verify_aes_cmac_with_profile(&key, &message, &tag, profile)
                    .unwrap();
                let mut wrong = tag.clone();
                wrong[0] ^= 1;
                for tag in [
                    &[][..],
                    wrong.as_slice(),
                    &tag[..tag_length - 1],
                    &[0; 17][..],
                ] {
                    assert!(matches!(
                        session.verify_aes_cmac_with_profile(&key, &message, tag, profile),
                        Err(Error::MacMismatch)
                    ));
                    session.info().unwrap();
                }
                session
                    .verify_aes_cmac_with_profile(&key, &message, &tag, profile)
                    .unwrap();
            }
            session.verify_aes_cmac(&key, &message, &tag).unwrap();
            let mut wrong = tag;
            wrong[0] ^= 1;
            assert!(matches!(
                session.verify_aes_cmac(&key, &message, &wrong),
                Err(Error::MacMismatch)
            ));
            session.info().unwrap();
        }
        session.close().unwrap();
        for (index, bad) in [
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::AllowedMechanisms(vec![MechanismType::AES_GCM]),
        ]
        .into_iter()
        .enumerate()
        {
            let bad_label = format!("cmac-policy-{}-{index}", size.length());
            let mut attrs = base.clone();
            for attr in &mut attrs {
                if attr.attribute_type() == bad.attribute_type() {
                    *attr = bad.clone();
                }
                match attr {
                    Attribute::Id(v) | Attribute::Label(v) => *v = bad_label.as_bytes().to_vec(),
                    _ => (),
                }
            }
            if !attrs
                .iter()
                .any(|a| a.attribute_type() == bad.attribute_type())
            {
                attrs.push(bad);
            }
            setup.create_object(&attrs).unwrap();
            for op in [MacOperation::Generate, MacOperation::Verify] {
                let supported = (index == 0 && op == MacOperation::Verify)
                    || (index == 1 && op == MacOperation::Generate);
                assert_eq!(
                    setup
                        .aes_cmac_capabilities(&reference(&bad_label), op)
                        .is_ok(),
                    supported
                );
                assert_eq!(
                    setup
                        .aes_cmac_capabilities_with_profile(
                            &reference(&bad_label),
                            op,
                            AesCmacProfile::General { tag_length: 8 }
                        )
                        .is_ok(),
                    supported && general_supported
                );
            }
        }
        for purpose in [
            AesKeyPurpose::Authentication,
            AesKeyPurpose::AuthenticationGeneral,
        ]
        .into_iter()
        .filter(|purpose| *purpose != AesKeyPurpose::AuthenticationGeneral || general_supported)
        {
            let general = purpose == AesKeyPurpose::AuthenticationGeneral;
            let label = format!("cmac-generated-{}-{general}", size.length());
            let request = AesKeyRequest {
                size,
                purpose,
                id: label.as_bytes(),
                label: label.as_bytes(),
            };
            let key = setup.generate_aes_key(&request).unwrap();
            let reads = key
                .read_attributes(&[
                    AttributeType::Sign,
                    AttributeType::Verify,
                    AttributeType::Encrypt,
                    AttributeType::Decrypt,
                    AttributeType::Wrap,
                    AttributeType::Unwrap,
                    AttributeType::Derive,
                    AttributeType::Sensitive,
                    AttributeType::Extractable,
                    AttributeType::AllowedMechanisms,
                ])
                .unwrap();
            for expected in [
                Attribute::Sign(true),
                Attribute::Verify(true),
                Attribute::Encrypt(false),
                Attribute::Decrypt(false),
                Attribute::Wrap(false),
                Attribute::Unwrap(false),
                Attribute::Derive(false),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::AllowedMechanisms(vec![if general {
                    MechanismType::AES_CMAC_GENERAL
                } else {
                    MechanismType::AES_CMAC
                }]),
            ] {
                assert!(reads.expose_values().contains(&expected));
            }
            let options = setup
                .aes_cmac_options(&reference(&label), MacOperation::Generate)
                .unwrap();
            assert_eq!((options.full, options.general), (!general, general));
            for profile in AesCmacProfile::ALL {
                assert_eq!(
                    options.supports(profile),
                    matches!(profile, AesCmacProfile::General { .. }) == general
                );
            }
            assert!(matches!(
                setup.generate_aes_key(&request),
                Err(Error::InvalidParameters(_))
            ));
        }
    }
    setup.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
