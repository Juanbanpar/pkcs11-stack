// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native general HMAC client profiles and reusable verification mismatches.
use pkcs11_client::{
    Authentication, Error, HmacAlgorithm, MacOperation, Pin, Provider, SessionMode,
};
use secrecy::SecretString;

#[test]
#[ignore = "requires the disposable Kryoptic runner after runtime HMAC fixtures"]
fn general_hmac_client_native_tags_and_reusable_mismatches() {
    use pkcs11_client::{HmacTagProfile, object_reference};
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=kdf-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let mut session = provider
        .management(
            &token,
            SessionMode::ReadOnly,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    for (index, algorithm) in HmacAlgorithm::ALL.into_iter().enumerate() {
        let key = object_reference(
            format!(
                "pkcs11:token=kdf-test;object=hmac-vector-{index}-false-{};type=secret-key",
                algorithm.tag_length()
            )
            .parse()
            .unwrap(),
        )
        .unwrap();
        let options = session.hmac_options(&key, MacOperation::Generate).unwrap();
        for profile in HmacTagProfile::choices(algorithm).into_iter().skip(1) {
            assert!(options.supports(algorithm, profile));
            let tag = session
                .mac_hmac_with_profile(&key, algorithm, b"client general", profile)
                .unwrap();
            assert_eq!(tag.len(), profile.tag_length(algorithm));
            assert_eq!(
                session
                    .hmac_reader(&key, algorithm, profile, &mut &b"client general"[..])
                    .unwrap(),
                tag
            );
            session
                .verify_hmac_reader(&key, algorithm, profile, &mut &b"client general"[..], &tag)
                .unwrap();
            assert!(matches!(
                session.verify_hmac_reader(&key, algorithm, profile, &mut &b"changed"[..], &tag),
                Err(Error::MacMismatch)
            ));
            session.state().unwrap();
            session
                .verify_hmac_with_profile(&key, algorithm, b"client general", &tag, profile)
                .unwrap();
            assert!(matches!(
                session.verify_hmac_with_profile(&key, algorithm, b"changed", &tag, profile),
                Err(Error::MacMismatch)
            ));
            session.state().unwrap();
        }
        if index == 0 {
            use std::{
                io::{Read, copy},
                process::{Command, Stdio},
            };
            let length = 17 * 1024 * 1024 + 3;
            let mut child = Command::new(std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap())
                .args([
                    "dgst",
                    "-sha256",
                    "-mac",
                    "HMAC",
                    "-macopt",
                    &format!("hexkey:{}", "0b".repeat(32)),
                    "-binary",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            copy(
                &mut std::io::repeat(0xA5).take(length),
                &mut child.stdin.take().unwrap(),
            )
            .unwrap();
            let expected = child.wait_with_output().unwrap();
            assert!(expected.status.success());
            for profile in [
                HmacTagProfile::Full,
                HmacTagProfile::General { tag_length: 16 },
            ] {
                let tag = session
                    .hmac_reader(
                        &key,
                        algorithm,
                        profile,
                        &mut std::io::repeat(0xA5).take(length),
                    )
                    .unwrap();
                assert_eq!(tag, expected.stdout[..profile.tag_length(algorithm)]);
                session
                    .verify_hmac_reader(
                        &key,
                        algorithm,
                        profile,
                        &mut std::io::repeat(0xA5).take(length),
                        &tag,
                    )
                    .unwrap();
                session.state().unwrap();
            }
        }
    }
    session.close().unwrap();
    provider.finalize().unwrap();
}

#[test]
#[ignore = "requires corrected Kryoptic runner after runtime HMAC fixtures"]
fn generated_general_hmac_client_restrictions_and_runtime_agreement() {
    use pkcs11_client::{
        Attribute, AttributeType, ErrorKind, HmacKeyRequest, HmacTagProfile, object_reference,
    };
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=kdf-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let options = provider.generation_capabilities(&token).unwrap();
    assert_eq!(options.hmac_general, HmacAlgorithm::ALL);
    assert_eq!(options.hmac, HmacAlgorithm::ALL);
    let mut setup = provider
        .management(
            &token,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    for (i, algorithm) in HmacAlgorithm::ALL.into_iter().enumerate() {
        let label = format!("client-generated-general-{i}");
        let key = object_reference(
            format!("pkcs11:token=kdf-test;object={label};type=secret-key")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let request = HmacKeyRequest {
            algorithm,
            id: label.as_bytes(),
            label: label.as_bytes(),
        };
        setup.generate_hmac_general_key(&request).unwrap();
        assert_eq!(
            setup
                .generate_hmac_general_key(&request)
                .unwrap_err()
                .kind(),
            ErrorKind::Input
        );
        assert!(setup.export_public(&key).is_err());
        let attrs = setup
            .inspect(
                &key,
                &[
                    AttributeType::Token,
                    AttributeType::Private,
                    AttributeType::Sensitive,
                    AttributeType::Extractable,
                    AttributeType::Encrypt,
                    AttributeType::Decrypt,
                    AttributeType::Derive,
                    AttributeType::Wrap,
                    AttributeType::Unwrap,
                    AttributeType::Sign,
                    AttributeType::Verify,
                    AttributeType::AllowedMechanisms,
                ],
            )
            .unwrap();
        for expected in [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Derive(false),
            Attribute::Wrap(false),
            Attribute::Unwrap(false),
            Attribute::Sign(true),
            Attribute::Verify(true),
            Attribute::AllowedMechanisms(vec![algorithm.general_mechanism()]),
        ] {
            assert!(attrs.iter().any(|a| {
                a.values
                    .as_ref()
                    .is_some_and(|v| v.expose_values().contains(&expected))
            }));
        }
        let mut ro = provider
            .management(&token, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        assert_eq!(
            ro.generate_hmac_general_key(&request).unwrap_err().kind(),
            ErrorKind::Policy
        );
        assert_eq!(
            ro.mac_hmac(&key, algorithm, b"message").unwrap_err().kind(),
            ErrorKind::Policy
        );
        assert!(ro.hkdf_options(&key).unwrap().is_empty());
        let profile = HmacTagProfile::General {
            tag_length: algorithm.tag_length() / 2,
        };
        let message = b"generated general HMAC\0\xff";
        let tag = ro
            .mac_hmac_with_profile(&key, algorithm, message, profile)
            .unwrap();
        assert_eq!(
            ro.hmac_reader(&key, algorithm, profile, &mut &message[..])
                .unwrap(),
            tag
        );
        ro.verify_hmac_reader(&key, algorithm, profile, &mut &message[..], &tag)
            .unwrap();
        assert!(matches!(
            ro.verify_hmac_with_profile(&key, algorithm, b"changed", &tag, profile),
            Err(Error::MacMismatch)
        ));
        ro.state().unwrap();
        let runtime_key = object_reference(
            format!("pkcs11:token=kdf-test;object=hmac-generated-general-{i};type=secret-key")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let reference = std::fs::read(
            std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap())
                .join(format!("hmac-generated-general-{i}.tag")),
        )
        .unwrap();
        assert_eq!(
            ro.mac_hmac_with_profile(&runtime_key, algorithm, message, profile)
                .unwrap(),
            reference
        );
        ro.verify_hmac_reader(
            &runtime_key,
            algorithm,
            profile,
            &mut &message[..],
            &reference,
        )
        .unwrap();
        ro.close().unwrap();
        setup.delete(&key).unwrap();
    }
    setup.close().unwrap();
    provider.finalize().unwrap();
}
