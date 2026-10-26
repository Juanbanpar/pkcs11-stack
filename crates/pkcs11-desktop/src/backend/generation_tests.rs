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
        let fields = registry.inspect(module, token, key).unwrap().fields;
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
                    super::KeyProfile::Classical(pkcs11_client::KeyOperationProfile::EcdhRaw(
                        curve,
                    )),
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
                    super::KeyProfile::Classical(pkcs11_client::KeyOperationProfile::AesKeyWrap(
                        size.length(),
                    )),
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
                    super::KeyProfile::Classical(pkcs11_client::KeyOperationProfile::AesKeyWrap(
                        size.length(),
                    )),
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

#[test]
#[ignore = "requires tools/test-softhsm.sh; PQC execution required with PKCS11_TEST_REQUIRE_PQC=1"]
fn software_token_pqc_generation_uses_advertised_choices_and_private_permissions() {
    use pkcs11_client::{
        Authentication, MlDsaParameterSet, MlKemOperation, MlKemParameterSet, PrivateKeyRef,
        SessionMode,
    };
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
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
    let choices = registry.capabilities(module, token).unwrap();
    let (_, uri) = registry.location(module, token).unwrap();
    let advertised = registry.modules[0]
        .provider
        .generation_capabilities(&uri)
        .unwrap();
    let pqc: Vec<_> = choices
        .into_iter()
        .filter(|kind| matches!(kind, GenerationKind::MlDsa(_) | GenerationKind::MlKem(_)))
        .collect();
    assert_eq!(
        pqc,
        advertised
            .ml_dsa
            .into_iter()
            .map(GenerationKind::MlDsa)
            .chain(advertised.ml_kem.into_iter().map(GenerationKind::MlKem))
            .collect::<Vec<_>>()
    );
    if std::env::var("PKCS11_TEST_REQUIRE_PQC").as_deref() == Ok("1") {
        assert_eq!(
            pqc,
            vec![
                GenerationKind::MlDsa(MlDsaParameterSet::MlDsa44),
                GenerationKind::MlDsa(MlDsaParameterSet::MlDsa65),
                GenerationKind::MlDsa(MlDsaParameterSet::MlDsa87),
                GenerationKind::MlKem(MlKemParameterSet::MlKem512),
                GenerationKind::MlKem(MlKemParameterSet::MlKem768),
                GenerationKind::MlKem(MlKemParameterSet::MlKem1024),
            ]
        );
    }
    for (index, &kind) in pqc.iter().enumerate() {
        let label = format!("desktop-pqc-{index}");
        let list = objects(
            registry.manage(
                module,
                token,
                ManagementAction::Generate {
                    kind,
                    id: vec![0xD7, 0x50, 0x51, index as u8],
                    label: label.as_bytes().to_vec(),
                    always_authenticate: false,
                },
            ),
            Some(BackendError::ManagementUnavailable),
        );
        assert!(list.iter().all(|entry| entry.label != label));
    }
    registry
        .login(
            module,
            token,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();
    for (index, &kind) in pqc.iter().enumerate() {
        let label = format!("desktop-pqc-{index}");
        let context = matches!(kind, GenerationKind::MlDsa(MlDsaParameterSet::MlDsa65));
        let action = |always_authenticate| ManagementAction::Generate {
            kind,
            id: vec![0xD7, 0x50, 0x51, index as u8],
            label: label.as_bytes().to_vec(),
            always_authenticate,
        };
        if matches!(kind, GenerationKind::MlKem(_)) {
            let list = objects(
                registry.manage(module, token, action(true)),
                Some(BackendError::InvalidForm),
            );
            assert!(list.iter().all(|entry| entry.label != label));
        }
        let list = objects(registry.manage(module, token, action(context)), None);
        let private = object(&list, &label, ObjectClass::PRIVATE_KEY);
        let public = object(&list, &label, ObjectClass::PUBLIC_KEY);
        assert_eq!(list.iter().filter(|entry| entry.label == label).count(), 2);
        let private_fields = registry.inspect(module, token, private).unwrap().fields;
        let public_fields = registry.inspect(module, token, public).unwrap().fields;
        let signing = matches!(kind, GenerationKind::MlDsa(_));
        for (fields, name, enabled) in [
            (&private_fields, "Persistent", true),
            (&private_fields, "Private", true),
            (&private_fields, "Sensitive", true),
            (&private_fields, "Extractable", false),
            (&private_fields, "Always authenticate", context),
            (&public_fields, "Private", false),
            (&public_fields, "Persistent", true),
            (
                &private_fields,
                if signing { "Sign" } else { "Decapsulate" },
                true,
            ),
            (
                &public_fields,
                if signing { "Verify" } else { "Encapsulate" },
                true,
            ),
        ] {
            assert!(
                fields.iter().any(|field| field.name == name
                    && field.value.as_deref() == Some(if enabled { "true" } else { "false" })),
                "{kind:?}: {name}"
            );
        }
        let (reference, _) = registry.reference(module, token, private).unwrap();
        let mut session = registry.modules[0]
            .provider
            .management(&uri, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        match kind {
            GenerationKind::MlDsa(parameter) => {
                let key = PrivateKeyRef::new(reference.uri().to_string().parse().unwrap()).unwrap();
                let capabilities = session.ml_dsa_capabilities(&key).unwrap();
                assert_eq!(capabilities.parameter_set, parameter);
                assert_eq!(capabilities.always_authenticate, context);
            }
            GenerationKind::MlKem(parameter) => {
                let capabilities = session
                    .ml_kem_capabilities(&reference, MlKemOperation::Decapsulate)
                    .unwrap();
                assert_eq!(capabilities.parameter_set, parameter);
            }
            _ => unreachable!(),
        }
        session.close().unwrap();
        let list = registry.objects(module, token).unwrap();
        assert_eq!(
            registry.inspect(module, token, private).unwrap_err(),
            BackendError::UnknownObject
        );
        assert!(list.iter().any(|entry| entry.label == label));
    }
    registry.close().unwrap();
}

#[test]
#[ignore = "requires tools/test-softhsm.sh; PQC execution required with PKCS11_TEST_REQUIRE_PQC=1"]
fn software_token_pqc_public_export_without_login_preserves_files_and_rejects_private_keys() {
    use pkcs11_client::{
        Authentication, MlDsaVerifyingKey, MlKemPublicKey, PublicKeyRef, SessionMode,
    };
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap())
        .join("desktop-pqc-export");
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
    let kinds: Vec<_> = registry
        .capabilities(module, token)
        .unwrap()
        .into_iter()
        .filter(|kind| matches!(kind, GenerationKind::MlDsa(_) | GenerationKind::MlKem(_)))
        .collect();
    if std::env::var("PKCS11_TEST_REQUIRE_PQC").as_deref() == Ok("1") {
        assert_eq!(kinds.len(), 6);
    }
    registry
        .login(
            module,
            token,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();
    for (index, &kind) in kinds.iter().enumerate() {
        let label = format!("desktop-export-{index}");
        let list = objects(
            registry.manage(
                module,
                token,
                ManagementAction::Generate {
                    kind,
                    id: vec![0xD7, 0x50, 0x52, index as u8],
                    label: label.as_bytes().to_vec(),
                    always_authenticate: false,
                },
            ),
            None,
        );
        let path = root.join(format!("private-{index}.der"));
        objects(
            registry.manage(
                module,
                token,
                ManagementAction::Export {
                    object: object(&list, &label, ObjectClass::PRIVATE_KEY),
                    path: path.clone(),
                },
            ),
            Some(BackendError::ExportUnavailable),
        );
        assert!(!path.exists());
    }
    registry.logout(module, token).unwrap();
    assert_eq!(
        registry.modules[0]
            .entry
            .tokens
            .iter()
            .find(|entry| entry.id == token)
            .unwrap()
            .login,
        LoginState::Public
    );
    for (index, &kind) in kinds.iter().enumerate() {
        let label = format!("desktop-export-{index}");
        let list = registry.objects(module, token).unwrap();
        let public = object(&list, &label, ObjectClass::PUBLIC_KEY);
        let (reference, _) = registry.reference(module, token, public).unwrap();
        let key = PublicKeyRef::new(reference.uri().to_string().parse().unwrap()).unwrap();
        let (_, uri) = registry.location(module, token).unwrap();
        let mut session = registry.modules[0]
            .provider
            .management(&uri, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        assert_eq!(
            session.state().unwrap(),
            pkcs11_client::SessionState::RoPublic
        );
        let expected = match kind {
            GenerationKind::MlDsa(_) => session.export_ml_dsa_public_key(&key),
            GenerationKind::MlKem(_) => session.export_ml_kem_public_key(&key),
            _ => unreachable!(),
        }
        .unwrap();
        session.close().unwrap();
        let path = root.join(format!("public-{index}.der"));
        objects(
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
        let der = std::fs::read(&path).unwrap();
        assert_eq!(der, expected);
        match kind {
            GenerationKind::MlDsa(parameter) => assert_eq!(
                MlDsaVerifyingKey::from_spki_der(&der)
                    .unwrap()
                    .parameter_set(),
                parameter
            ),
            GenerationKind::MlKem(parameter) => assert_eq!(
                MlKemPublicKey::from_spki_der(&der).unwrap().parameter_set(),
                parameter
            ),
            _ => unreachable!(),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let stale = root.join(format!("stale-{index}.der"));
        let list = objects(
            registry.manage(
                module,
                token,
                ManagementAction::Export {
                    object: public,
                    path: stale.clone(),
                },
            ),
            Some(BackendError::UnknownObject),
        );
        assert!(!stale.exists());
        objects(
            registry.manage(
                module,
                token,
                ManagementAction::Export {
                    object: object(&list, &label, ObjectClass::PUBLIC_KEY),
                    path: path.clone(),
                },
            ),
            Some(BackendError::FileWrite),
        );
        assert_eq!(std::fs::read(&path).unwrap(), der);
    }
    registry.close().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
