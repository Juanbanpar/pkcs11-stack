// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{
    CryptoJob, CryptoMode, CryptoScope, LoginRole, ObjectEntry, SecretInput, SignatureProfile,
};
use pkcs11_client::{ClassicalPublicKeyPurpose as Purpose, DigestAlgorithm, ObjectClass};
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
        other => panic!("unexpected import result {other:?}"),
    }
}
fn object(list: &[ObjectEntry], label: &str, class: ObjectClass) -> ResourceId {
    list.iter()
        .find(|object| object.label == label && object.class == Some(class))
        .unwrap()
        .id
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn software_token_public_import_permissions_usage_and_invalid_files() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
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
    let message = root.join("desktop-import-message");
    std::fs::write(&message, b"desktop public key import").unwrap();
    let mut list;
    for (source_id, label) in [(1, "rsa"), (2, "p256"), (3, "p384"), (4, "p521")] {
        let imported_label = format!("desktop-import-{label}");
        let action = || ManagementAction::ImportPublicKey {
            path: root.join(format!("{source_id:02X}-public.der")),
            id: vec![0xFA, 0xDD, source_id],
            label: imported_label.as_bytes().to_vec(),
            purpose: Purpose::Verification,
        };
        list = objects(registry.manage(module, token, action()), None);
        let count = list.len();
        list = objects(
            registry.manage(module, token, action()),
            Some(BackendError::Client(pkcs11_client::ErrorKind::Input)),
        );
        assert_eq!(list.len(), count);
        let key = object(&list, &imported_label, ObjectClass::PUBLIC_KEY);
        let fields = registry.inspect(module, token, key).unwrap().fields;
        for (name, value) in [
            ("Verify", true),
            ("Encrypt", false),
            ("Wrap", false),
            ("Derive", false),
            ("Private", false),
        ] {
            assert!(
                fields.iter().any(|f| f.name == name
                    && f.value.as_deref() == Some(if value { "true" } else { "false" })),
                "{name}"
            );
        }
        let source = CryptoScope {
            module,
            token,
            object: object(&list, label, ObjectClass::PRIVATE_KEY),
            mode: CryptoMode::Sign,
        };
        let parameters = match registry.crypto_options(source, true).unwrap() {
            BackendResult::CryptoOptions { options, .. } => options
                .into_iter()
                .find(|option| {
                    matches!(option.parameters, SignatureProfile::Classical(p) if p.digest == DigestAlgorithm::Sha256)
                })
                .unwrap()
                .parameters,
            _ => panic!("signing choices"),
        };
        let signature = root.join(format!("desktop-import-{label}.sig"));
        let job = || CryptoJob {
            parameters,
            software_hashing: true,
            domain_context: vec![],
            input: message.clone(),
            signature: signature.clone(),
            context: None,
        };
        list = objects(registry.crypto(source, job()).unwrap(), None);
        let key = object(&list, &imported_label, ObjectClass::PUBLIC_KEY);
        let scope = CryptoScope {
            module,
            token,
            object: key,
            mode: CryptoMode::Verify,
        };
        assert!(matches!(
            registry.crypto(scope, job()).unwrap(),
            BackendResult::Verified { .. }
        ));
        let exported = root.join(format!("desktop-import-{label}.der"));
        list = objects(
            registry.manage(
                module,
                token,
                ManagementAction::Export {
                    object: key,
                    path: exported.clone(),
                },
            ),
            None,
        );
        assert_eq!(
            std::fs::read(&exported).unwrap(),
            std::fs::read(root.join(format!("{source_id:02X}-public.der"))).unwrap()
        );
        assert!(list.iter().any(|o| o.label == imported_label));
    }
    for (filename, purpose) in [
        ("01-cert.der", Purpose::Verification),
        ("cipher-private.der", Purpose::Verification),
        ("02-public.der", Purpose::Encryption),
    ] {
        list = objects(
            registry.manage(
                module,
                token,
                ManagementAction::ImportPublicKey {
                    path: root.join(filename),
                    id: vec![0xFA, 0xDE],
                    label: b"invalid-public-import".to_vec(),
                    purpose,
                },
            ),
            Some(BackendError::PublicKeyImportInput),
        );
        assert!(!list.iter().any(|o| o.label == "invalid-public-import"));
    }
    list = objects(
        registry.manage(
            module,
            token,
            ManagementAction::ImportPublicKey {
                path: root.join("cipher-public.der"),
                id: vec![0xFA, 0xDF],
                label: b"desktop-import-encryption".to_vec(),
                purpose: Purpose::Encryption,
            },
        ),
        None,
    );
    let imported = object(&list, "desktop-import-encryption", ObjectClass::PUBLIC_KEY);
    let fields = registry.inspect(module, token, imported).unwrap().fields;
    for (name, value) in [
        ("Encrypt", true),
        ("Verify", false),
        ("Wrap", false),
        ("Derive", false),
    ] {
        assert!(
            fields.iter().any(|f| f.name == name
                && f.value.as_deref() == Some(if value { "true" } else { "false" }))
        );
    }
    registry.logout(module, token).unwrap();
    objects(
        registry.manage(
            module,
            token,
            ManagementAction::ImportPublicKey {
                path: root.join("cipher-public.der"),
                id: vec![0xFA, 0xE0],
                label: b"unauthenticated-import".to_vec(),
                purpose: Purpose::Encryption,
            },
        ),
        Some(BackendError::ManagementUnavailable),
    );
    registry.close().unwrap();
}
