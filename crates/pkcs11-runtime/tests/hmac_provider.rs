// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native HMAC interoperation and authentication-only key generation.
use pkcs11_runtime::{
    Attribute, AttributeType, Authentication, Error, HmacAlgorithm, HmacKeyRequest, HmacTagProfile,
    KeyType, MacOperation, MechanismType, Module, ObjectClass, ObjectRef, Pin, SessionMode,
};
use secrecy::SecretString;
use std::{
    io::Write,
    process::{Command, Stdio},
};
fn reference(token: &str, label: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token={token};object={label};type=secret-key")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn template(label: &str, kind: KeyType, value: Vec<u8>) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(kind),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Verify(true),
        Attribute::Derive(false),
        Attribute::Encrypt(false),
        Attribute::Decrypt(false),
        Attribute::Wrap(false),
        Attribute::Unwrap(false),
        Attribute::Id(label.as_bytes().to_vec()),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Value(value),
    ]
}
#[test]
#[ignore = "requires the disposable SoftHSM or Kryoptic runner"]
fn hmac_openssl_key_types_lengths_permissions_and_generated_keys() {
    let kdf = std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref() == Ok("1");
    assert!(kdf || std::env::var("PKCS11_TEST_ISOLATED").as_deref() == Ok("1"));
    let module = Module::load(
        std::env::var_os(if kdf {
            "PKCS11_TEST_KDF_MODULE"
        } else {
            "PKCS11_TEST_MODULE"
        })
        .unwrap(),
    )
    .unwrap();
    let token_name = if kdf { "kdf-test" } else { "client-test" };
    let token = module
        .resolve_token_uri(&format!("pkcs11:token={token_name}").parse().unwrap())
        .unwrap();
    let pin = SecretString::from("12345678");
    let mut setup = token.open_session(SessionMode::ReadWrite).unwrap();
    setup
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, (algorithm, kind)) in HmacAlgorithm::ALL
        .into_iter()
        .zip([
            KeyType::SHA256_HMAC,
            KeyType::SHA384_HMAC,
            KeyType::SHA512_HMAC,
            KeyType::SHA224_HMAC,
            KeyType::SHA512_224_HMAC,
            KeyType::SHA512_256_HMAC,
            KeyType::SHA3_224_HMAC,
            KeyType::SHA3_256_HMAC,
            KeyType::SHA3_384_HMAC,
            KeyType::SHA3_512_HMAC,
        ])
        .enumerate()
    {
        let advertised = token.mechanisms().unwrap().contains(&algorithm.mechanism());
        if kdf || index < 4 {
            assert!(advertised, "required HMAC mechanism {algorithm}");
        }
        let generation = token.hmac_generation_options().unwrap();
        if !advertised {
            assert!(!generation.contains(&algorithm));
            continue;
        }
        assert!(generation.contains(&algorithm));
        for (typed, kind) in [(false, KeyType::GENERIC_SECRET), (true, kind)] {
            for length in if kdf && typed {
                vec![algorithm.tag_length()]
            } else if kdf {
                vec![20, algorithm.tag_length(), 200]
            } else {
                vec![algorithm.tag_length(), 200]
            } {
                let label = format!("hmac-vector-{index}-{typed}-{length}");
                setup
                    .create_object(&template(&label, kind, vec![0x0B; length]))
                    .unwrap_or_else(|error| {
                        panic!("HMAC fixture {index}, typed={typed}, length={length}: {error}")
                    });
                let key = reference(token_name, &label);
                let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
                let caps = ro.hmac_capabilities(&key, MacOperation::Generate).unwrap();
                assert_eq!(caps.key_length, length);
                for a in HmacAlgorithm::ALL {
                    let supported = token.mechanisms().unwrap().contains(&a.mechanism());
                    assert_eq!(caps.supports(a), supported && (!typed || a == algorithm));
                }
                for message in [vec![], b"Hi There".to_vec(), vec![0xA5; 4097]] {
                    let mut child = Command::new("openssl")
                        .args([
                            "dgst",
                            &format!("-{}", algorithm.to_string().strip_prefix("hmac-").unwrap()),
                            "-mac",
                            "HMAC",
                            "-macopt",
                            &format!("hexkey:{}", "0b".repeat(length)),
                            "-binary",
                        ])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .unwrap();
                    child.stdin.take().unwrap().write_all(&message).unwrap();
                    let expected = child.wait_with_output().unwrap();
                    assert!(expected.status.success());
                    let tag = ro.mac_hmac(&key, algorithm, &message).unwrap();
                    assert_eq!(tag, expected.stdout);
                    let mut stream = ro
                        .start_hmac(&key, algorithm, HmacTagProfile::Full)
                        .unwrap();
                    stream.update(&[]).unwrap();
                    for chunk in message.chunks(31) {
                        stream.update(chunk).unwrap();
                    }
                    assert_eq!(stream.finish().unwrap(), expected.stdout);
                    let mut stream = ro
                        .start_hmac_verification(&key, algorithm, HmacTagProfile::Full)
                        .unwrap();
                    for chunk in message.chunks(17) {
                        stream.update(chunk).unwrap();
                    }
                    stream.finish(&tag).unwrap();
                    ro.verify_hmac(&key, algorithm, &message, &tag).unwrap();
                    let options = ro.hmac_options(&key, MacOperation::Generate).unwrap();
                    let general = options.general.is_some_and(|caps| caps.supports(algorithm));
                    if kdf {
                        assert!(general);
                    }
                    for tag_profile in HmacTagProfile::choices(algorithm).into_iter().skip(1) {
                        if !general {
                            assert!(matches!(
                                ro.mac_hmac_with_profile(&key, algorithm, &message, tag_profile),
                                Err(Error::UnsupportedMac)
                            ));
                            continue;
                        }
                        let expected = &expected.stdout[..tag_profile.tag_length(algorithm)];
                        let tag = ro
                            .mac_hmac_with_profile(&key, algorithm, &message, tag_profile)
                            .unwrap();
                        assert_eq!(tag, expected);
                        let mut stream = ro.start_hmac(&key, algorithm, tag_profile).unwrap();
                        for chunk in message.chunks(31) {
                            stream.update(chunk).unwrap();
                        }
                        assert_eq!(stream.finish().unwrap(), expected);
                        let mut stream = ro
                            .start_hmac_verification(&key, algorithm, tag_profile)
                            .unwrap();
                        for chunk in message.chunks(17) {
                            stream.update(chunk).unwrap();
                        }
                        stream.finish(&tag).unwrap();
                        ro.verify_hmac_with_profile(&key, algorithm, &message, &tag, tag_profile)
                            .unwrap();
                        let mut wrong = tag.clone();
                        wrong[0] ^= 1;
                        for supplied in [&[][..], wrong.as_slice(), &tag[..tag.len() - 1]] {
                            assert!(matches!(
                                ro.verify_hmac_with_profile(
                                    &key,
                                    algorithm,
                                    &message,
                                    supplied,
                                    tag_profile
                                ),
                                Err(Error::MacMismatch)
                            ));
                            ro.info().unwrap();
                            let mut stream = ro
                                .start_hmac_verification(&key, algorithm, tag_profile)
                                .unwrap();
                            for chunk in message.chunks(31) {
                                stream.update(chunk).unwrap();
                            }
                            assert!(matches!(stream.finish(supplied), Err(Error::MacMismatch)));
                            ro.info().unwrap();
                        }
                    }
                    let mut wrong = tag.clone();
                    wrong[0] ^= 1;
                    for tag in [&[][..], wrong.as_slice(), &tag[..tag.len() - 1]] {
                        assert!(matches!(
                            ro.verify_hmac(&key, algorithm, &message, tag),
                            Err(Error::MacMismatch)
                        ));
                        ro.info().unwrap();
                    }
                    ro.verify_hmac(&key, algorithm, &message, &tag).unwrap();
                }
                if kdf {
                    let mut stream = ro
                        .start_hmac(&key, algorithm, HmacTagProfile::Full)
                        .unwrap();
                    stream.update(b"abandoned generation").unwrap();
                    stream.cancel().unwrap();
                    let mut stream = ro
                        .start_hmac_verification(&key, algorithm, HmacTagProfile::Full)
                        .unwrap();
                    stream.update(b"abandoned verification").unwrap();
                    stream.cancel().unwrap();
                    let tag = ro.mac_hmac(&key, algorithm, b"after cancellation").unwrap();
                    ro.verify_hmac(&key, algorithm, b"after cancellation", &tag)
                        .unwrap();
                }
                ro.close().unwrap();
            }
        }
        for (case, bad) in [
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::AllowedMechanisms(vec![MechanismType::HKDF_DERIVE]),
            Attribute::Value(vec![0x0B; 15]),
            Attribute::Value(vec![0x0B; 4097]),
            Attribute::KeyType(KeyType::SHA_1_HMAC),
        ]
        .into_iter()
        .enumerate()
        {
            let label = format!("hmac-policy-{index}-{case}");
            let mut attrs = template(&label, KeyType::GENERIC_SECRET, vec![0x0B; 32]);
            if let Some(attr) = attrs
                .iter_mut()
                .find(|a| a.attribute_type() == bad.attribute_type())
            {
                *attr = bad;
            } else {
                attrs.push(bad);
            }
            if case == 7 {
                if let Some(Attribute::Value(value)) = attrs
                    .iter_mut()
                    .find(|a| a.attribute_type() == AttributeType::Value)
                {
                    *value = vec![0x0B; 20];
                }
            }
            setup.create_object(&attrs).unwrap();
            let key = reference(token_name, &label);
            for op in [MacOperation::Generate, MacOperation::Verify] {
                let permitted = (case == 0 && op == MacOperation::Verify)
                    || (case == 1 && op == MacOperation::Generate);
                assert_eq!(setup.hmac_capabilities(&key, op).is_ok(), permitted);
                if !permitted {
                    let result = if op == MacOperation::Generate {
                        setup.mac_hmac(&key, algorithm, b"message").map(|_| ())
                    } else {
                        setup.verify_hmac(
                            &key,
                            algorithm,
                            b"message",
                            &vec![0; algorithm.tag_length()],
                        )
                    };
                    assert!(matches!(result, Err(Error::UnsupportedMac)));
                    setup.info().unwrap();
                }
            }
        }
        let label = format!("hmac-generated-{index}");
        let request = HmacKeyRequest {
            algorithm,
            id: label.as_bytes(),
            label: label.as_bytes(),
        };
        {
            let key = setup.generate_hmac_key(&request).unwrap();
            let attrs = key
                .read_attributes(&[
                    AttributeType::KeyType,
                    AttributeType::ValueLen,
                    AttributeType::Sign,
                    AttributeType::Verify,
                    AttributeType::Derive,
                    AttributeType::Encrypt,
                    AttributeType::Decrypt,
                    AttributeType::Wrap,
                    AttributeType::Unwrap,
                    AttributeType::Sensitive,
                    AttributeType::Extractable,
                    AttributeType::AllowedMechanisms,
                ])
                .unwrap();
            let mechanism = algorithm.mechanism();
            for expected in [
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::ValueLen(algorithm.tag_length().try_into().unwrap()),
                Attribute::Sign(true),
                Attribute::Verify(true),
                Attribute::Derive(false),
                Attribute::Encrypt(false),
                Attribute::Decrypt(false),
                Attribute::Wrap(false),
                Attribute::Unwrap(false),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::AllowedMechanisms(vec![mechanism]),
            ] {
                assert!(attrs.expose_values().contains(&expected));
            }
        }
        assert!(matches!(
            setup.generate_hmac_key(&request),
            Err(Error::InvalidParameters(_))
        ));
        let key = reference(token_name, &label);
        let caps = setup
            .hmac_capabilities(&key, MacOperation::Generate)
            .unwrap();
        for a in HmacAlgorithm::ALL {
            assert_eq!(caps.supports(a), a == algorithm);
        }
        assert!(
            setup
                .hmac_options(&key, MacOperation::Generate)
                .unwrap()
                .general
                .is_none()
        );
        let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
        assert!(matches!(
            ro.generate_hmac_key(&request),
            Err(Error::ReadWriteRequired)
        ));
        ro.close().unwrap();
    }
    setup.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}

#[test]
#[ignore = "requires corrected disposable Kryoptic runner"]
fn generated_general_hmac_keys_permissions_profiles_and_reuse() {
    use pkcs11_runtime::{AttributeInfo, HmacTagProfile};
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let info = token
        .mechanism_info(MechanismType::GENERIC_SECRET_KEY_GEN)
        .unwrap();
    assert_eq!(info.min_key_size(), 0);
    assert!(info.max_key_size() >= 4096 * 8);
    assert_eq!(
        token.hmac_general_generation_options().unwrap(),
        HmacAlgorithm::ALL
    );
    let pin = SecretString::from("12345678");
    let mut setup = token.open_session(SessionMode::ReadWrite).unwrap();
    setup
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, algorithm) in HmacAlgorithm::ALL.into_iter().enumerate() {
        let label = format!("hmac-generated-general-{index}");
        let request = HmacKeyRequest {
            algorithm,
            id: label.as_bytes(),
            label: label.as_bytes(),
        };
        {
            let key = setup.generate_hmac_general_key(&request).unwrap();
            let attrs = key
                .read_attributes(&[
                    AttributeType::Class,
                    AttributeType::KeyType,
                    AttributeType::ValueLen,
                    AttributeType::Token,
                    AttributeType::Private,
                    AttributeType::Sensitive,
                    AttributeType::Extractable,
                    AttributeType::AlwaysSensitive,
                    AttributeType::NeverExtractable,
                    AttributeType::Local,
                    AttributeType::KeyGenMechanism,
                    AttributeType::Sign,
                    AttributeType::Verify,
                    AttributeType::Encrypt,
                    AttributeType::Decrypt,
                    AttributeType::Wrap,
                    AttributeType::Unwrap,
                    AttributeType::Derive,
                    AttributeType::AllowedMechanisms,
                ])
                .unwrap();
            for expected in [
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::ValueLen(algorithm.tag_length().try_into().unwrap()),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::AlwaysSensitive(true),
                Attribute::NeverExtractable(true),
                Attribute::Local(true),
                Attribute::KeyGenMechanism(MechanismType::GENERIC_SECRET_KEY_GEN),
                Attribute::Sign(true),
                Attribute::Verify(true),
                Attribute::Encrypt(false),
                Attribute::Decrypt(false),
                Attribute::Wrap(false),
                Attribute::Unwrap(false),
                Attribute::Derive(false),
                Attribute::AllowedMechanisms(vec![algorithm.general_mechanism()]),
            ] {
                assert!(attrs.expose_values().contains(&expected), "{expected:?}");
            }
            assert!(matches!(
                key.attribute_info(&[AttributeType::Value])
                    .unwrap()
                    .as_slice(),
                [AttributeInfo::Sensitive]
            ));
        }
        assert!(matches!(
            setup.generate_hmac_general_key(&request),
            Err(Error::InvalidParameters(_))
        ));
        let key = reference("kdf-test", &label);
        let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
        assert!(matches!(
            ro.generate_hmac_general_key(&request),
            Err(Error::ReadWriteRequired)
        ));
        for operation in [MacOperation::Generate, MacOperation::Verify] {
            let options = ro.hmac_options(&key, operation).unwrap();
            assert!(options.full.is_none());
            let caps = options.general.unwrap();
            assert_eq!(caps.key_length, algorithm.tag_length());
            for a in HmacAlgorithm::ALL {
                assert_eq!(caps.supports(a), a == algorithm);
            }
        }
        assert!(matches!(
            ro.mac_hmac(&key, algorithm, b"message"),
            Err(Error::UnsupportedMac)
        ));
        for wrong in HmacAlgorithm::ALL.into_iter().filter(|a| *a != algorithm) {
            assert!(matches!(
                ro.mac_hmac_with_profile(
                    &key,
                    wrong,
                    b"message",
                    HmacTagProfile::General {
                        tag_length: wrong.tag_length()
                    }
                ),
                Err(Error::UnsupportedMac)
            ));
        }
        for message in [
            &[][..],
            &b"generated general HMAC\0\xff"[..],
            &vec![0xA5; 4097][..],
        ] {
            let full_profile = HmacTagProfile::General {
                tag_length: algorithm.tag_length(),
            };
            let full = ro
                .mac_hmac_with_profile(&key, algorithm, message, full_profile)
                .unwrap();
            for profile in HmacTagProfile::choices(algorithm).into_iter().skip(1) {
                let tag = ro
                    .mac_hmac_with_profile(&key, algorithm, message, profile)
                    .unwrap();
                assert_eq!(tag, &full[..profile.tag_length(algorithm)]);
                let mut stream = ro.start_hmac(&key, algorithm, profile).unwrap();
                for chunk in message.chunks(31) {
                    stream.update(chunk).unwrap();
                }
                assert_eq!(stream.finish().unwrap(), tag);
                ro.verify_hmac_with_profile(&key, algorithm, message, &tag, profile)
                    .unwrap();
                let mut bad = tag.clone();
                bad[0] ^= 1;
                for bad in [&bad[..], &tag[..tag.len() - 1]] {
                    assert!(matches!(
                        ro.verify_hmac_with_profile(&key, algorithm, message, bad, profile),
                        Err(Error::MacMismatch)
                    ));
                    ro.info().unwrap();
                }
            }
        }
        let profile = HmacTagProfile::General {
            tag_length: algorithm.tag_length() / 2,
        };
        let tag = ro
            .mac_hmac_with_profile(&key, algorithm, b"generated general HMAC\0\xff", profile)
            .unwrap();
        std::fs::write(
            std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap())
                .join(format!("hmac-generated-general-{index}.tag")),
            tag,
        )
        .unwrap();
        ro.close().unwrap();
    }
    setup.close().unwrap();
    module.finalize().unwrap();
}
