// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{
    BackendResult, GenerationKind, KeyProfile, LoginRole, ManagementAction, ObjectEntry,
    ResourceId, SecretInput,
};
use pkcs11_client::{Attribute, AttributeType, ObjectClass};
use std::path::{Path, PathBuf};

fn scope(
    module: ResourceId,
    token: ResourceId,
    objects: &[ObjectEntry],
    label: &str,
    mode: CryptoMode,
) -> CryptoScope {
    let class = if mode == CryptoMode::Encapsulate {
        ObjectClass::PUBLIC_KEY
    } else {
        ObjectClass::PRIVATE_KEY
    };
    CryptoScope {
        module,
        token,
        object: objects
            .iter()
            .find(|entry| entry.label == label && entry.class == Some(class))
            .unwrap()
            .id,
        mode,
    }
}
fn managed(result: BackendResult, expected: Option<BackendError>) -> Vec<ObjectEntry> {
    match result {
        BackendResult::Managed {
            error,
            objects: Some(objects),
            ..
        } => {
            assert_eq!(error, expected);
            objects
        }
        other => panic!("unexpected key result {other:?}"),
    }
}
fn job(mode: CryptoMode, path: &Path, index: u8, case: u8) -> KeyJob {
    let id = vec![0xD7, 0x50, 0x56, index, case];
    let label = format!("desktop-kem-secret-{index}-{case}").into_bytes();
    if mode == CryptoMode::Encapsulate {
        KeyJob::Encapsulate {
            output: path.into(),
            id,
            label,
        }
    } else {
        KeyJob::Decapsulate {
            input: path.into(),
            id,
            label,
        }
    }
}
#[test]
fn kem_directions_profiles_and_unknown_targets_fail_without_file_effects() {
    assert!(operation(CryptoMode::Derive).is_err());
    let profile = KeyProfile::MlKem(MlKemParameterSet::MlKem768);
    for mode in [
        CryptoMode::Sign,
        CryptoMode::Verify,
        CryptoMode::Derive,
        CryptoMode::Wrap,
        CryptoMode::Unwrap,
        CryptoMode::Encrypt,
        CryptoMode::Decrypt,
    ] {
        assert!(!profile.supports(mode));
    }
    assert!(profile.supports(CryptoMode::Encapsulate));
    assert!(profile.supports(CryptoMode::Decapsulate));
    let registry = Registry::default();
    let scope = CryptoScope {
        module: ResourceId(1),
        token: ResourceId(2),
        object: ResourceId(3),
        mode: CryptoMode::Encapsulate,
    };
    assert!(matches!(
        registry.key_options(scope),
        Err(BackendError::UnknownModule)
    ));
    assert_eq!(
        registry.kem_action(
            scope,
            MlKemParameterSet::MlKem768,
            job(
                CryptoMode::Encapsulate,
                Path::new("unused-ciphertext"),
                0,
                0
            )
        ),
        Err(BackendError::UnknownModule)
    );
}

#[test]
#[ignore = "requires tools/test-ml-kem.sh"]
fn software_token_ml_kem_files_permissions_implicit_rejection_and_failures() {
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
    let parameters: Vec<_> = registry
        .capabilities(module, token)
        .unwrap()
        .into_iter()
        .filter_map(|kind| {
            if let GenerationKind::MlKem(parameter) = kind {
                Some(parameter)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        parameters,
        [
            MlKemParameterSet::MlKem512,
            MlKemParameterSet::MlKem768,
            MlKemParameterSet::MlKem1024
        ]
    );
    registry
        .login(
            module,
            token,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();
    let root = std::env::temp_dir().join(format!("desktop-ml-kem-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    for (index, parameter) in parameters.into_iter().enumerate() {
        let index = index as u8;
        let label = format!("desktop-ml-kem-{index}");
        let mut objects = managed(
            registry.manage(
                module,
                token,
                ManagementAction::Generate {
                    kind: GenerationKind::MlKem(parameter),
                    id: vec![0xD7, 0x50, 0x55, index],
                    label: label.as_bytes().to_vec(),
                    always_authenticate: false,
                },
            ),
            None,
        );
        let profile = KeyProfile::MlKem(parameter);
        for mode in [CryptoMode::Encapsulate, CryptoMode::Decapsulate] {
            let target = scope(module, token, &objects, &label, mode);
            assert!(
                matches!(registry.key_options(target), Ok(BackendResult::KeyOptions { profile: actual, scope }) if actual == profile && scope == target)
            );
        }
        let output = root.join(format!("ciphertext-{index}"));
        let target = scope(module, token, &objects, &label, CryptoMode::Encapsulate);
        objects = managed(
            registry.key_operation(
                target,
                profile,
                KeyJob::Encapsulate {
                    output: output.clone(),
                    id: Vec::new(),
                    label: b"invalid identity".to_vec(),
                },
            ),
            Some(BackendError::KeyOperationInput),
        );
        assert!(!output.exists());

        let target = scope(module, token, &objects, &label, CryptoMode::Encapsulate);
        let wrong = if parameter == MlKemParameterSet::MlKem512 {
            MlKemParameterSet::MlKem768
        } else {
            MlKemParameterSet::MlKem512
        };
        objects = managed(
            registry.key_operation(
                target,
                KeyProfile::MlKem(wrong),
                job(CryptoMode::Encapsulate, &output, index, 9),
            ),
            Some(BackendError::KeyOperationUnavailable),
        );
        assert!(!output.exists());
        let mut target = scope(module, token, &objects, &label, CryptoMode::Decapsulate);
        target.mode = CryptoMode::Encapsulate;
        objects = managed(
            registry.key_operation(
                target,
                profile,
                job(CryptoMode::Encapsulate, &output, index, 9),
            ),
            Some(BackendError::KeyOperationUnavailable),
        );
        assert!(!output.exists());
        let target = scope(module, token, &objects, &label, CryptoMode::Encapsulate);
        objects = managed(
            registry.key_operation(
                target,
                profile,
                job(CryptoMode::Encapsulate, &output, index, 1),
            ),
            None,
        );
        assert!(matches!(
            registry.key_options(target),
            Err(BackendError::UnknownObject)
        ));
        let ciphertext = std::fs::read(&output).unwrap();
        assert_eq!(ciphertext.len(), parameter.ciphertext_length());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let target = scope(module, token, &objects, &label, CryptoMode::Encapsulate);
        objects = managed(
            registry.key_operation(
                target,
                profile,
                job(CryptoMode::Encapsulate, &output, index, 5),
            ),
            Some(BackendError::FileWrite),
        );
        assert_eq!(std::fs::read(&output).unwrap(), ciphertext);
        assert!(
            !objects
                .iter()
                .any(|entry| entry.label == format!("desktop-kem-secret-{index}-5"))
        );
        let duplicate = root.join(format!("duplicate-{index}"));
        let target = scope(module, token, &objects, &label, CryptoMode::Encapsulate);
        objects = managed(
            registry.key_operation(
                target,
                profile,
                job(CryptoMode::Encapsulate, &duplicate, index, 1),
            ),
            Some(BackendError::Client(pkcs11_client::ErrorKind::Input)),
        );
        assert_eq!(std::fs::metadata(duplicate).unwrap().len(), 0);
        let invalid = root.join(format!("invalid-{index}"));
        for length in [0, ciphertext.len() - 1, ciphertext.len() + 1] {
            std::fs::write(&invalid, vec![0; length]).unwrap();
            let target = scope(module, token, &objects, &label, CryptoMode::Decapsulate);
            objects = managed(
                registry.key_operation(
                    target,
                    profile,
                    job(CryptoMode::Decapsulate, &invalid, index, 4),
                ),
                Some(BackendError::KeyOperationInput),
            );
            assert!(
                !objects
                    .iter()
                    .any(|entry| entry.label == format!("desktop-kem-secret-{index}-4"))
            );
            assert_eq!(std::fs::metadata(&invalid).unwrap().len(), length as u64);
        }
        let target = scope(module, token, &objects, &label, CryptoMode::Decapsulate);
        objects = managed(
            registry.key_operation(
                target,
                profile,
                job(CryptoMode::Decapsulate, &output, index, 2),
            ),
            None,
        );
        assert_eq!(std::fs::read(&output).unwrap(), ciphertext);
        let mut altered = ciphertext.clone();
        altered[0] ^= 1;
        std::fs::write(&invalid, &altered).unwrap();
        let target = scope(module, token, &objects, &label, CryptoMode::Decapsulate);
        objects = managed(
            registry.key_operation(
                target,
                profile,
                job(CryptoMode::Decapsulate, &invalid, index, 3),
            ),
            None,
        );
        assert_eq!(std::fs::read(&invalid).unwrap(), altered);
        let (_, uri) = registry.location(module, token).unwrap();
        for case in 1..=3 {
            let secret = objects
                .iter()
                .find(|entry| entry.label == format!("desktop-kem-secret-{index}-{case}"))
                .unwrap();
            let reference = registry.reference(module, token, secret.id).unwrap().0;
            let module_entry = &registry.modules[0];
            read_session(module_entry, &uri, SessionMode::ReadOnly, |session| {
                let reads = session
                    .inspect(
                        &reference,
                        &[
                            AttributeType::Sensitive,
                            AttributeType::Extractable,
                            AttributeType::Derive,
                            AttributeType::Encrypt,
                            AttributeType::Decrypt,
                            AttributeType::Sign,
                            AttributeType::Verify,
                            AttributeType::Wrap,
                            AttributeType::Unwrap,
                            AttributeType::Private,
                            AttributeType::ValueLen,
                            AttributeType::KeyType,
                        ],
                    )
                    .unwrap();
                for expected in [
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Derive(true),
                    Attribute::Encrypt(false),
                    Attribute::Decrypt(false),
                    Attribute::Sign(false),
                    Attribute::Verify(false),
                    Attribute::Wrap(false),
                    Attribute::Unwrap(false),
                    Attribute::Private(true),
                    Attribute::ValueLen(32.into()),
                    Attribute::KeyType(pkcs11_client::KeyType::GENERIC_SECRET),
                ] {
                    assert!(reads.iter().any(|read| {
                        read.values
                            .as_ref()
                            .is_some_and(|values| values.expose_values().contains(&expected))
                    }));
                }
                assert!(session.export_public(&reference).is_err());
                assert!(session.export_value(&reference).is_err());
                Ok(())
            })
            .unwrap();
        }
        registry.logout(module, token).unwrap();
        objects = registry.objects(module, token).unwrap();
        assert!(
            !objects
                .iter()
                .any(|entry| entry.class == Some(ObjectClass::SECRET_KEY)
                    && entry.label.starts_with("desktop-kem-secret"))
        );
        let denied = root.join(format!("logged-out-{index}"));
        let target = scope(module, token, &objects, &label, CryptoMode::Encapsulate);
        assert!(matches!(
            registry.key_options(target),
            Err(BackendError::KeyOperationUnavailable)
        ));
        managed(
            registry.key_operation(
                target,
                profile,
                job(CryptoMode::Encapsulate, &denied, index, 8),
            ),
            Some(BackendError::KeyOperationUnavailable),
        );
        assert!(!denied.exists());
        registry
            .login(
                module,
                token,
                LoginRole::User,
                SecretInput::Value("12345678".into()),
            )
            .unwrap();
    }
    registry.close().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires tools/test-ml-kem.sh"]
fn software_token_ml_kem_import_validates_files_identity_authentication_and_duplicates() {
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
    let supported = registry
        .capabilities(module, token)
        .unwrap()
        .iter()
        .filter(|kind| matches!(kind, GenerationKind::MlKem(_)))
        .count();
    assert_eq!(supported, 3);
    let root = std::env::temp_dir().join(format!("desktop-ml-kem-import-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let fixtures =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkcs11-client/tests/fixtures");
    for (index, name) in ["mlkem512", "mlkem768", "mlkem1024"]
        .into_iter()
        .enumerate()
    {
        let path = fixtures.join(format!("{name}.spki.der"));
        let label = format!("desktop-import-{name}");
        let action = || ManagementAction::ImportMlKem {
            path: path.clone(),
            id: vec![0xD7, 0x50, 0x57, index as u8],
            label: label.as_bytes().to_vec(),
        };
        managed(
            registry.manage(module, token, action()),
            Some(BackendError::ManagementUnavailable),
        );
        registry
            .login(
                module,
                token,
                LoginRole::User,
                SecretInput::Value("12345678".into()),
            )
            .unwrap();
        let invalid = root.join("invalid.der");
        for bytes in [
            Vec::new(),
            vec![0; 2049],
            std::fs::read(fixtures.join("mldsa44.spki.der")).unwrap(),
            std::fs::read(fixtures.join("rsa.der")).unwrap(),
        ] {
            std::fs::write(&invalid, bytes).unwrap();
            let listed = managed(
                registry.manage(
                    module,
                    token,
                    ManagementAction::ImportMlKem {
                        path: invalid.clone(),
                        id: vec![0xD7, 0x50, 0x57, index as u8],
                        label: label.as_bytes().to_vec(),
                    },
                ),
                Some(BackendError::MlKemImportInput),
            );
            assert!(!listed.iter().any(|entry| entry.label == label));
        }
        let listed = managed(
            registry.manage(
                module,
                token,
                ManagementAction::ImportMlKem {
                    path: path.clone(),
                    id: Vec::new(),
                    label: label.as_bytes().to_vec(),
                },
            ),
            Some(BackendError::MlKemImportInput),
        );
        assert!(!listed.iter().any(|entry| entry.label == label));
        let listed = managed(registry.manage(module, token, action()), None);
        let target = scope(module, token, &listed, &label, CryptoMode::Encapsulate);
        assert!(matches!(
            registry.key_options(target),
            Ok(BackendResult::KeyOptions {
                profile: KeyProfile::MlKem(_),
                ..
            })
        ));
        let exported = root.join(format!("{name}.der"));
        managed(
            registry.manage(
                module,
                token,
                ManagementAction::Export {
                    object: target.object,
                    path: exported.clone(),
                },
            ),
            None,
        );
        assert_eq!(
            std::fs::read(exported).unwrap(),
            std::fs::read(&path).unwrap()
        );
        let listed = managed(registry.manage(module, token, action()), None);
        assert_eq!(
            listed.iter().filter(|entry| entry.label == label).count(),
            2
        );
        assert!(
            listed
                .iter()
                .filter(|entry| entry.label == label)
                .all(|entry| entry.ambiguous)
        );
        let target = scope(module, token, &listed, &label, CryptoMode::Encapsulate);
        assert!(matches!(
            registry.key_options(target),
            Err(BackendError::AmbiguousObject)
        ));
        registry.logout(module, token).unwrap();
        let listed = registry.objects(module, token).unwrap();
        assert_eq!(
            listed.iter().filter(|entry| entry.label == label).count(),
            2
        );
    }
    registry.close().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
