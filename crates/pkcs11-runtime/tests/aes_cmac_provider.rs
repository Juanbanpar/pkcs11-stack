// SPDX-License-Identifier: MIT OR Apache-2.0
//! Full-tag CMAC against independent OpenSSL, including restrictive key policy.
use pkcs11_runtime::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, Attribute, AttributeType, Authentication, Error,
    KeyType, MacOperation, MechanismType, Module, ObjectClass, ObjectRef, Pin, SessionMode,
};
use secrecy::SecretString;
use std::{
    io::Write,
    process::{Command, Stdio},
};
fn reference(label: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token=client-test;object={label};type=secret-key")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn aes_cmac_independent_tags_permissions_generation_and_reuse() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let module = Module::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=client-test".parse().unwrap())
        .unwrap();
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
            }
        }
        let label = format!("cmac-generated-{}", size.length());
        let request = AesKeyRequest {
            size,
            purpose: AesKeyPurpose::Authentication,
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
            Attribute::AllowedMechanisms(vec![MechanismType::AES_CMAC]),
        ] {
            assert!(reads.expose_values().contains(&expected));
        }
        assert!(matches!(
            setup.generate_aes_key(&request),
            Err(Error::InvalidParameters(_))
        ));
    }
    setup.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
