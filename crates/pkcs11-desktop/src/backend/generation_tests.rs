// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use pkcs11_client::{AesKeyPurpose, AesKeySize, NamedCurve, ObjectClass};

fn objects(result: BackendResult, expected: Option<BackendError>) -> Vec<ObjectEntry> {
    match result {
        BackendResult::Managed {
            objects: Some(objects),
            error,
            ..
        } => {
            assert_eq!(error, expected);
            objects
        }
        result => panic!("unexpected result {result:?}"),
    }
}
fn object(list: &[ObjectEntry], label: &str, class: ObjectClass) -> ResourceId {
    list.iter()
        .find(|entry| entry.label == label && entry.class == Some(class))
        .unwrap()
        .id
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn software_token_typed_generation_permissions_and_use() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap())
        .join("desktop-generation");
    std::fs::create_dir(&root).unwrap();
    let mut registry = Registry::default();
    let module = registry
        .load(&PathBuf::from(
            std::env::var_os("PKCS11_TEST_MODULE").unwrap(),
        ))
        .unwrap();
    let token = registry.modules[0]
        .entry
        .tokens
        .iter()
        .find(|entry| entry.label == "client-test")
        .unwrap()
        .id;
    registry
        .login(
            module,
            token,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();
    let choices = registry.capabilities(module, token).unwrap();
    let curves = [NamedCurve::P256, NamedCurve::P384, NamedCurve::P521];
    let sizes = [
        AesKeySize::Bits128,
        AesKeySize::Bits192,
        AesKeySize::Bits256,
    ];
    for (index, kind) in curves
        .into_iter()
        .map(GenerationKind::Ecdh)
        .chain(sizes.into_iter().flat_map(|size| {
            [AesKeyPurpose::Encryption, AesKeyPurpose::Wrapping]
                .map(|purpose| GenerationKind::Aes(size, purpose))
        }))
        .enumerate()
    {
        assert!(choices.contains(&kind));
        let label = format!("desktop-generated-{index}");
        let action = |context| ManagementAction::Generate {
            kind,
            id: vec![0xA7, index as u8],
            label: label.as_bytes().to_vec(),
            always_authenticate: context,
        };
        let list = objects(
            registry.manage(module, token, action(true)),
            Some(BackendError::InvalidForm),
        );
        assert!(list.iter().all(|entry| entry.label != label));
        let list = objects(registry.manage(module, token, action(false)), None);
        let class = if matches!(kind, GenerationKind::Ecdh(_)) {
            ObjectClass::PRIVATE_KEY
        } else {
            ObjectClass::SECRET_KEY
        };
        let key = object(&list, &label, class);
        let fields = registry.inspect(module, token, key).unwrap();
        for (name, enabled) in [
            ("Private", true),
            ("Sensitive", true),
            ("Extractable", false),
            ("Sign", false),
            ("Derive", matches!(kind, GenerationKind::Ecdh(_))),
            (
                "Encrypt",
                matches!(kind, GenerationKind::Aes(_, AesKeyPurpose::Encryption)),
            ),
            (
                "Decrypt",
                matches!(kind, GenerationKind::Aes(_, AesKeyPurpose::Encryption)),
            ),
            (
                "Wrap",
                matches!(kind, GenerationKind::Aes(_, AesKeyPurpose::Wrapping)),
            ),
            (
                "Unwrap",
                matches!(kind, GenerationKind::Aes(_, AesKeyPurpose::Wrapping)),
            ),
        ] {
            if class == ObjectClass::PRIVATE_KEY && matches!(name, "Encrypt" | "Wrap") {
                continue;
            }
            assert!(
                fields.iter().any(|field| field.name == name
                    && field.value.as_deref() == Some(if enabled { "true" } else { "false" })),
                "{kind:?} {name}"
            );
        }
        let duplicate = objects(
            registry.manage(module, token, action(false)),
            Some(BackendError::Client(pkcs11_client::ErrorKind::Input)),
        );
        let key = object(&duplicate, &label, class);
        let denied = root.join(format!("secret-{index}"));
        let list = objects(
            registry.manage(
                module,
                token,
                ManagementAction::Export {
                    object: key,
                    path: denied.clone(),
                },
            ),
            Some(BackendError::ExportUnavailable),
        );
        assert!(!denied.exists());
        if let GenerationKind::Ecdh(curve) = kind {
            let public = object(&list, &label, ObjectClass::PUBLIC_KEY);
            let path = root.join(format!("peer-{index}.der"));
            let list = objects(
                registry.manage(
                    module,
                    token,
                    ManagementAction::Export {
                        object: public,
                        path: path.clone(),
                    },
                ),
                None,
            );
            assert_eq!(
                pkcs11_client::EcdhPeer::from_spki_der(&std::fs::read(&path).unwrap())
                    .unwrap()
                    .curve(),
                curve
            );
            let scope = CryptoScope {
                module,
                token,
                object: object(&list, &label, class),
                mode: CryptoMode::Derive,
            };
            // A self-peer is a local operation fixture, not a peer-authentication protocol.
            let list = objects(
                registry.key_operation(
                    scope,
                    pkcs11_client::KeyOperationProfile::EcdhRaw(curve),
                    KeyJob::Derive {
                        peer: path,
                        id: vec![0xA6, index as u8],
                        label: format!("desktop-derived-{index}").into_bytes(),
                    },
                ),
                None,
            );
            assert!(
                list.iter()
                    .any(|entry| entry.label == format!("desktop-derived-{index}"))
            );
        } else if let GenerationKind::Aes(size, AesKeyPurpose::Wrapping) = kind {
            let scope = CryptoScope {
                module,
                token,
                object: object(&list, &label, class),
                mode: CryptoMode::Wrap,
            };
            let wrapped = root.join(format!("wrapped-{index}"));
            let list = objects(
                registry.key_operation(
                    scope,
                    pkcs11_client::KeyOperationProfile::AesKeyWrap(size.length()),
                    KeyJob::Wrap {
                        target: object(&list, "transferable", ObjectClass::SECRET_KEY),
                        output: wrapped.clone(),
                    },
                ),
                None,
            );
            assert_eq!(std::fs::read(&wrapped).unwrap().len(), 24);
            let scope = CryptoScope {
                module,
                token,
                object: object(&list, &label, class),
                mode: CryptoMode::Unwrap,
            };
            objects(
                registry.key_operation(
                    scope,
                    pkcs11_client::KeyOperationProfile::AesKeyWrap(size.length()),
                    KeyJob::Unwrap {
                        input: wrapped,
                        id: vec![0xA6, index as u8],
                        label: format!("desktop-unwrapped-{index}").into_bytes(),
                    },
                ),
                None,
            );
        }
    }
    registry.close().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
