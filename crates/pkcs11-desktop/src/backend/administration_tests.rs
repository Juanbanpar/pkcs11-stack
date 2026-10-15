// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{
    BackendCommand, BackendEvent, LoginRole, ManagementAction, RequestId, SecretInput,
};
use pkcs11_client::Provider;
#[track_caller]
fn inventory(result: BackendResult, expected: Option<BackendError>) {
    match result {
        BackendResult::Modules { error, .. } => assert_eq!(error, expected),
        result => panic!("unexpected result: {result:?}"),
    }
}
fn target(registry: &Registry, label: &str) -> TokenEntry {
    registry.modules[0]
        .entry
        .tokens
        .iter()
        .find(|token| token.label == label)
        .unwrap()
        .clone()
}
#[track_caller]
fn execute(
    registry: &mut Registry,
    module: ResourceId,
    entry: &TokenEntry,
    action: AdministrationAction,
    error: Option<BackendError>,
) {
    inventory(
        registry.administer(
            module,
            entry.id,
            entry.initialization.clone(),
            entry.login,
            action,
        ),
        error,
    );
}
#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn software_token_initialization_pin_roles_stale_targets_and_reauthentication() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let path = std::env::var_os("PKCS11_TEST_MODULE").unwrap();
    let mut registry = Registry::default();
    let module = registry.load(std::path::Path::new(&path)).unwrap();
    let free = registry.modules[0]
        .entry
        .tokens
        .iter()
        .find(|entry| !entry.initialized)
        .unwrap()
        .clone();
    assert!(
        free.can_administer(AdministrationKind::InitializeToken),
        "{free:?}"
    );
    execute(
        &mut registry,
        module,
        &free,
        AdministrationAction::InitializeToken {
            so_pin: "87654321".into(),
            label: "desktop-admin".into(),
        },
        None,
    );
    let entry = target(&registry, "desktop-admin");
    assert!(entry.initialized);
    assert!(!entry.user_pin_initialized);
    assert!(registry.modules[0].authentication.is_empty());
    execute(
        &mut registry,
        module,
        &entry,
        AdministrationAction::InitializeUserPin {
            new_pin: "12345678".into(),
        },
        Some(BackendError::AdministrationUnavailable),
    );
    registry
        .login(
            module,
            entry.id,
            LoginRole::SecurityOfficer,
            SecretInput::Value("87654321".into()),
        )
        .unwrap();
    let entry = target(&registry, "desktop-admin");
    let mut stale = entry.initialization.clone();
    stale.serial.push('x');
    inventory(
        registry.administer(
            module,
            entry.id,
            stale,
            entry.login,
            AdministrationAction::InitializeToken {
                so_pin: "87654321".into(),
                label: "must-not-erase".into(),
            },
        ),
        Some(BackendError::AdministrationUnavailable),
    );
    assert_eq!(
        target(&registry, "desktop-admin").login,
        LoginState::SecurityOfficer
    );
    execute(
        &mut registry,
        module,
        &entry,
        AdministrationAction::InitializeUserPin {
            new_pin: "12345678".into(),
        },
        None,
    );
    let entry = target(&registry, "desktop-admin");
    assert_eq!(entry.login, LoginState::Public);
    assert!(entry.user_pin_initialized);
    registry
        .login(
            module,
            entry.id,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();
    let entry = target(&registry, "desktop-admin");
    execute(
        &mut registry,
        module,
        &entry,
        AdministrationAction::ChangePin {
            old_pin: "incorrect".into(),
            new_pin: "23456789".into(),
        },
        Some(BackendError::AdministrationFailed),
    );
    assert_eq!(target(&registry, "desktop-admin").login, LoginState::Public);
    registry
        .login(
            module,
            entry.id,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();
    let entry = target(&registry, "desktop-admin");
    execute(
        &mut registry,
        module,
        &entry,
        AdministrationAction::ChangePin {
            old_pin: "12345678".into(),
            new_pin: "23456789".into(),
        },
        None,
    );
    let entry = target(&registry, "desktop-admin");
    registry
        .login(
            module,
            entry.id,
            LoginRole::User,
            SecretInput::Value("23456789".into()),
        )
        .unwrap();
    let fixture = std::path::PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap())
        .join("admin-certificate.der");
    let document = include_bytes!("../../../pkcs11-client/tests/fixtures/rsa.der");
    std::fs::write(&fixture, document).unwrap();
    assert!(matches!(
        registry.manage(
            module,
            entry.id,
            ManagementAction::ImportCertificate {
                path: fixture,
                id: vec![0xAF],
                label: b"erase-me".to_vec()
            }
        ),
        BackendResult::Managed { error: None, .. }
    ));
    assert!(
        registry
            .objects(module, entry.id)
            .unwrap()
            .iter()
            .any(|object| object.label == "erase-me")
    );
    registry.logout(module, entry.id).unwrap();
    registry
        .login(
            module,
            entry.id,
            LoginRole::SecurityOfficer,
            SecretInput::Value("87654321".into()),
        )
        .unwrap();
    let entry = target(&registry, "desktop-admin");
    execute(
        &mut registry,
        module,
        &entry,
        AdministrationAction::ChangePin {
            old_pin: "87654321".into(),
            new_pin: "98765432".into(),
        },
        None,
    );
    let entry = target(&registry, "desktop-admin");
    registry
        .login(
            module,
            entry.id,
            LoginRole::SecurityOfficer,
            SecretInput::Value("98765432".into()),
        )
        .unwrap();
    let other = target(&registry, "client-test");
    registry
        .login(
            module,
            other.id,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();
    assert_eq!(registry.modules[0].authentication.len(), 2);
    let entry = target(&registry, "desktop-admin");
    execute(
        &mut registry,
        module,
        &entry,
        AdministrationAction::InitializeToken {
            so_pin: "incorrect".into(),
            label: "must-not-erase".into(),
        },
        Some(BackendError::AdministrationFailed),
    );
    assert!(registry.modules[0].authentication.is_empty());
    assert!(target(&registry, "desktop-admin").user_pin_initialized);
    assert!(
        registry
            .objects(module, entry.id)
            .unwrap()
            .iter()
            .any(|object| object.label == "erase-me")
    );
    registry
        .login(
            module,
            entry.id,
            LoginRole::SecurityOfficer,
            SecretInput::Value("98765432".into()),
        )
        .unwrap();
    registry
        .login(
            module,
            other.id,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();
    let entry = target(&registry, "desktop-admin");
    execute(
        &mut registry,
        module,
        &entry,
        AdministrationAction::InitializeToken {
            so_pin: "98765432".into(),
            label: "desktop-admin-erased".into(),
        },
        None,
    );
    assert!(registry.modules[0].authentication.is_empty());
    assert_eq!(target(&registry, "client-test").login, LoginState::Public);
    let erased = target(&registry, "desktop-admin-erased");
    assert!(!erased.user_pin_initialized);
    assert!(registry.objects(module, erased.id).unwrap().is_empty());
    // A stale resource cannot authorize another erase, even if the slot is reused.
    execute(
        &mut registry,
        module,
        &entry,
        AdministrationAction::InitializeToken {
            so_pin: "98765432".into(),
            label: "stale-erase".into(),
        },
        Some(BackendError::UnknownToken),
    );
    registry.modules[0].administration_cleanup_failed = true;
    let result = registry.execute(BackendCommand::Refresh {
        id: RequestId(100),
        module,
    });
    assert!(matches!(
        result,
        BackendEvent::Completed {
            result: Ok(BackendResult::Modules {
                error: Some(BackendError::AdministrationCleanup),
                ..
            }),
            ..
        }
    ));
    assert!(registry.modules[0].entry.tokens.is_empty());
    assert_eq!(
        registry.discover(0),
        Err(BackendError::AdministrationCleanup)
    );
    registry.close().unwrap();
    Provider::load(path).unwrap().finalize().unwrap();
}
