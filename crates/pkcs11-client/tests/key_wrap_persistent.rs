// SPDX-License-Identifier: MIT OR Apache-2.0
//! AES KW/KWP interchange and output policy on the disposable Kryoptic store.
use pkcs11_client::*;
use secrecy::{ExposeSecret, SecretString};
use std::{path::Path, process::Command};

fn key(group: u8, index: u8) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;id=%F4%{group:02X}%{index:02X};type=secret-key")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn fixture(
    session: &mut pkcs11_runtime::Session<'_>,
    identity: (u8, u8),
    length: usize,
    wrapping: bool,
    extractable: bool,
    trusted: bool,
    allowed: Vec<MechanismType>,
) {
    let (group, index) = identity;
    let mut template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(extractable),
        Attribute::Wrap(wrapping),
        Attribute::Unwrap(wrapping),
        Attribute::Encrypt(!wrapping),
        Attribute::Decrypt(!wrapping),
        Attribute::Sign(false),
        Attribute::Verify(false),
        Attribute::Derive(false),
        Attribute::WrapWithTrusted(trusted),
        Attribute::Id(vec![0xF4, group, index]),
        Attribute::Label(format!("kwp-{group:02X}-{index}").into_bytes()),
        Attribute::Value((0..length as u8).collect()),
    ];
    if !allowed.is_empty() {
        template.push(Attribute::AllowedMechanisms(allowed));
    }
    session.create_object(&template).unwrap();
}
fn openssl(
    root: &Path,
    algorithm: AesKeyWrapAlgorithm,
    wrapping_length: usize,
    length: usize,
    decrypt: bool,
) -> Vec<u8> {
    let input = root.join("kwp-input");
    let output = root.join("kwp-output");
    let kek: String = (0..wrapping_length).map(|b| format!("{b:02x}")).collect();
    let cipher = format!(
        "-id-aes{}-wrap{}",
        wrapping_length * 8,
        if algorithm == AesKeyWrapAlgorithm::Kwp {
            "-pad"
        } else {
            ""
        }
    );
    if !decrypt {
        std::fs::write(&input, (0..length as u8).collect::<Vec<_>>()).unwrap();
    }
    let result = Command::new(std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap())
        .args([
            "enc",
            &cipher,
            if decrypt { "-d" } else { "-e" },
            "-K",
            &kek,
            "-iv",
            if algorithm == AesKeyWrapAlgorithm::Kwp {
                "A65959A6"
            } else {
                "A6A6A6A6A6A6A6A6"
            },
            "-in",
        ])
        .arg(&input)
        .arg("-out")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::read(output).unwrap()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn aes_kw_and_kwp_interchange_permissions_and_failures() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let path = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let root = std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let pin = SecretString::from("12345678");
    let token_uri = "pkcs11:token=kdf-test".parse().unwrap();
    let module = Module::load(&path).unwrap();
    let token = module.resolve_token_uri(&token_uri).unwrap();
    let mut raw = token.open_session(SessionMode::ReadWrite).unwrap();
    raw.authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (i, length) in [16, 24, 32].into_iter().enumerate() {
        fixture(
            &mut raw,
            (0xA0, i as u8),
            length,
            true,
            false,
            false,
            vec![MechanismType::AES_KEY_WRAP, MechanismType::AES_KEY_WRAP_KWP],
        );
        fixture(
            &mut raw,
            (0xA1, i as u8),
            length,
            false,
            true,
            false,
            vec![],
        );
    }
    fixture(&mut raw, (0xA2, 0), 16, false, false, false, vec![]);
    fixture(&mut raw, (0xA2, 1), 16, false, true, true, vec![]);
    fixture(
        &mut raw,
        (0xA2, 2),
        16,
        true,
        false,
        false,
        vec![MechanismType::AES_KEY_WRAP_KWP],
    );
    fixture(
        &mut raw,
        (0xA2, 3),
        16,
        true,
        false,
        false,
        vec![MechanismType::AES_KEY_WRAP_PAD],
    );
    raw.close().unwrap();
    drop(token);
    module.finalize().unwrap();
    let provider = Provider::load(&path).unwrap();
    let open = |mode| {
        let mut session = provider
            .management(&token_uri, mode, Authentication::None)
            .unwrap();
        if matches!(
            session.state().unwrap(),
            SessionState::RoPublic | SessionState::RwPublic
        ) {
            session
                .authenticate(Authentication::User(Pin::Value(&pin)))
                .unwrap();
        }
        session
    };
    let mut session = open(SessionMode::ReadWrite);
    for (kek_index, wrapping_length) in [16, 24, 32].into_iter().enumerate() {
        let wrapping = key(0xA0, kek_index as u8);
        let caps = session
            .aes_key_wrap_options(&wrapping, KeyOperation::Wrap)
            .unwrap();
        assert_eq!(
            caps,
            AesKeyWrapCapabilities {
                key_length: wrapping_length,
                kw: true,
                kwp: true
            }
        );
        for (target_index, length) in [16, 24, 32].into_iter().enumerate() {
            let target = key(0xA1, target_index as u8);
            for (algorithm_index, algorithm) in [AesKeyWrapAlgorithm::Kw, AesKeyWrapAlgorithm::Kwp]
                .into_iter()
                .enumerate()
            {
                let wrapped = session
                    .wrap_with_algorithm(&wrapping, &WrapRequest { target: &target }, algorithm)
                    .unwrap();
                assert_eq!(
                    wrapped,
                    openssl(&root, algorithm, wrapping_length, length, false)
                );
                std::fs::write(root.join("kwp-input"), &wrapped).unwrap();
                assert_eq!(
                    openssl(&root, algorithm, wrapping_length, length, true),
                    (0..length as u8).collect::<Vec<_>>()
                );
                let index = (kek_index * 6 + target_index * 2 + algorithm_index) as u8;
                let id = [0xF4, 0xA3, index];
                let request = UnwrapRequest {
                    wrapped: &wrapped,
                    identity: SecretKeyIdentity {
                        id: &id,
                        label: b"unwrapped KW/KWP",
                    },
                };
                let mut ro = open(SessionMode::ReadOnly);
                assert!(matches!(
                    ro.unwrap_with_algorithm(&wrapping, &request, algorithm),
                    Err(Error::Runtime(pkcs11_runtime::Error::ReadWriteRequired))
                ));
                ro.close().unwrap();
                session
                    .unwrap_with_algorithm(&wrapping, &request, algorithm)
                    .unwrap();
                assert!(
                    session
                        .unwrap_with_algorithm(&wrapping, &request, algorithm)
                        .is_err()
                );
                let unwrapped = key(0xA3, index);
                let attrs = session
                    .inspect(
                        &unwrapped,
                        &[
                            AttributeType::Sensitive,
                            AttributeType::Extractable,
                            AttributeType::Wrap,
                            AttributeType::Unwrap,
                            AttributeType::Derive,
                            AttributeType::Sign,
                            AttributeType::Verify,
                            AttributeType::Encrypt,
                            AttributeType::Decrypt,
                        ],
                    )
                    .unwrap();
                for expected in [
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Wrap(false),
                    Attribute::Unwrap(false),
                    Attribute::Derive(false),
                    Attribute::Sign(false),
                    Attribute::Verify(false),
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                ] {
                    assert!(attrs.iter().any(|a| {
                        a.values
                            .as_ref()
                            .is_some_and(|v| v.expose_values().contains(&expected))
                    }));
                }
                assert!(session.export_public(&unwrapped).is_err());
                let nonce = [index; 12];
                let encrypted = session
                    .encrypt_aes_gcm(
                        &target,
                        &AesGcmEncryptRequest {
                            nonce: &nonce,
                            aad: b"key proof",
                            plaintext: b"KW/KWP output challenge",
                        },
                    )
                    .unwrap();
                let plaintext = session
                    .decrypt_aes_gcm(
                        &unwrapped,
                        &AesGcmDecryptRequest {
                            nonce: &nonce,
                            aad: b"key proof",
                            ciphertext: &encrypted,
                        },
                    )
                    .unwrap();
                assert_eq!(plaintext.expose_secret(), b"KW/KWP output challenge");
                session.delete(&unwrapped).unwrap();
            }
        }
    }
    let wrapping = key(0xA0, 0);
    for target in [&wrapping, &key(0xA2, 0), &key(0xA2, 1)] {
        assert!(matches!(
            session.wrap_with_algorithm(
                &wrapping,
                &WrapRequest { target },
                AesKeyWrapAlgorithm::Kwp
            ),
            Err(Error::Runtime(
                pkcs11_runtime::Error::UnsupportedKeyOperation
            ))
        ));
        session.state().unwrap();
    }
    let only_kwp = key(0xA2, 2);
    let caps = session
        .aes_key_wrap_options(&only_kwp, KeyOperation::Wrap)
        .unwrap();
    assert!(!caps.kw && caps.kwp);
    let target = key(0xA1, 0);
    assert!(
        session
            .wrap(&only_kwp, &WrapRequest { target: &target })
            .is_err()
    );
    assert!(
        session
            .aes_key_wrap_options(&key(0xA2, 3), KeyOperation::Wrap)
            .is_err()
    );
    let wrapped = session
        .wrap_with_algorithm(
            &only_kwp,
            &WrapRequest { target: &target },
            AesKeyWrapAlgorithm::Kwp,
        )
        .unwrap();
    session.close().unwrap();
    for (algorithm, blob) in [
        // KWP accepts arbitrary byte lengths, but this API only creates AES keys.
        (
            AesKeyWrapAlgorithm::Kwp,
            openssl(&root, AesKeyWrapAlgorithm::Kwp, 16, 20, false),
        ),
        (AesKeyWrapAlgorithm::Kw, wrapped.clone()),
        (AesKeyWrapAlgorithm::Kwp, {
            let mut bad = wrapped;
            bad[0] ^= 1;
            bad
        }),
    ] {
        let mut session = open(SessionMode::ReadWrite);
        assert!(matches!(
            session.unwrap_with_algorithm(
                &wrapping,
                &UnwrapRequest {
                    wrapped: &blob,
                    identity: SecretKeyIdentity {
                        id: b"invalid-kwp",
                        label: b"invalid KW/KWP"
                    }
                },
                algorithm
            ),
            Err(Error::Runtime(pkcs11_runtime::Error::Backend { .. }))
        ));
        assert!(session.state().is_err());
        session.close().unwrap();
        let mut check = open(SessionMode::ReadOnly);
        let invalid = ObjectRef::new(
            "pkcs11:token=kdf-test;object=invalid%20KW%2FKWP;type=secret-key"
                .parse()
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            check.inspect(&invalid, &[]),
            Err(Error::Runtime(pkcs11_runtime::Error::NotFound("object")))
        ));
        check.close().unwrap();
    }
    provider.finalize().unwrap();
}
