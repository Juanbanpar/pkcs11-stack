// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{LoginRole, ObjectEntry, SecretInput};
use pkcs11_client::{ObjectClass, Provider};
fn object(objects: &[ObjectEntry], label: &str, class: ObjectClass) -> ResourceId {
    objects
        .iter()
        .find(|entry| entry.label == label && entry.class == Some(class))
        .unwrap()
        .id
}
fn managed(result: BackendResult, error: Option<BackendError>) -> Vec<ObjectEntry> {
    match result {
        BackendResult::Managed {
            objects: Some(objects),
            error: actual,
            ..
        } => {
            assert_eq!(actual, error);
            objects
        }
        result => panic!("unexpected result {result:?}"),
    }
}
#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn software_token_derivation_wrapping_unwrapping_permissions_and_failures() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let fixtures = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let directory = fixtures.join("desktop-key-operations");
    std::fs::create_dir(&directory).unwrap();
    let module_path = PathBuf::from(std::env::var_os("PKCS11_TEST_MODULE").unwrap());
    let mut registry = Registry::default();
    let module = registry.load(&module_path).unwrap();
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
    let mut objects = registry.objects(module, token).unwrap();
    let scope = |objects: &[ObjectEntry], label: &str, mode| CryptoScope {
        module,
        token,
        object: object(
            objects,
            label,
            if mode == CryptoMode::Derive {
                ObjectClass::PRIVATE_KEY
            } else {
                ObjectClass::SECRET_KEY
            },
        ),
        mode,
    };
    let wrapping = scope(&objects, "wrapping", CryptoMode::Wrap);
    let profile = match registry.key_options(wrapping).unwrap() {
        BackendResult::KeyOptions { profile, .. } => profile,
        _ => panic!("profile"),
    };
    assert_eq!(
        profile,
        KeyProfile::Classical(KeyOperationProfile::AesKeyWrap(32))
    );
    let output = directory.join("wrapped");
    let target = object(&objects, "transferable", ObjectClass::SECRET_KEY);
    objects = managed(
        registry.key_operation(
            wrapping,
            profile,
            KeyJob::Wrap {
                target,
                output: output.clone(),
            },
        ),
        None,
    );
    let bytes = std::fs::read(&output).unwrap();
    // RFC 3394 section 4.3: AES-256 KEK wrapping the 128-bit test key.
    assert_eq!(
        bytes,
        [
            0x64, 0xe8, 0xc3, 0xf9, 0xce, 0x0f, 0x5b, 0xa2, 0x63, 0xe9, 0x77, 0x79, 0x05, 0x81,
            0x8a, 0x2a, 0x93, 0xc8, 0x19, 0x1e, 0x7d, 0x6e, 0x8a, 0xe7
        ]
    );
    let current = scope(&objects, "wrapping", CryptoMode::Wrap);
    let target = object(&objects, "transferable", ObjectClass::SECRET_KEY);
    objects = managed(
        registry.key_operation(
            current,
            profile,
            KeyJob::Wrap {
                target,
                output: output.clone(),
            },
        ),
        Some(BackendError::FileWrite),
    );
    assert_eq!(std::fs::read(&output).unwrap(), bytes);
    let current = scope(&objects, "wrapping", CryptoMode::Wrap);
    let target = object(&objects, "nonextractable", ObjectClass::SECRET_KEY);
    let rejected = directory.join("denied");
    objects = managed(
        registry.key_operation(
            current,
            profile,
            KeyJob::Wrap {
                target,
                output: rejected.clone(),
            },
        ),
        Some(BackendError::Client(pkcs11_client::ErrorKind::Policy)),
    );
    assert!(std::fs::read(&rejected).unwrap().is_empty());
    let current = scope(&objects, "wrapping", CryptoMode::Unwrap);
    objects = managed(
        registry.key_operation(
            current,
            profile,
            KeyJob::Unwrap {
                input: output.clone(),
                id: vec![0x80],
                label: b"unwrapped".to_vec(),
            },
        ),
        None,
    );
    let unwrapped = object(&objects, "unwrapped", ObjectClass::SECRET_KEY);
    let fields = registry.inspect(module, token, unwrapped).unwrap().fields;
    for (name, value) in [
        ("Sensitive", "true"),
        ("Extractable", "false"),
        ("Private", "true"),
        ("Encrypt", "true"),
        ("Decrypt", "true"),
        ("Wrap", "false"),
        ("Unwrap", "false"),
        ("Derive", "false"),
    ] {
        assert!(
            fields
                .iter()
                .any(|field| field.name == name && field.value.as_deref() == Some(value)),
            "{name}"
        );
    }
    // Newly unwrapped material is independently exercised without exporting it.
    let plain = directory.join("plain");
    std::fs::write(&plain, [0u8; 16]).unwrap();
    let cipher = directory.join("cipher");
    let status = std::process::Command::new("pkcs11-tool")
        .arg("--module")
        .arg(&module_path)
        .args([
            "--token-label",
            "client-test",
            "--login",
            "--pin",
            "12345678",
            "--encrypt",
            "--mechanism",
            "AES-ECB",
            "--id",
            "80",
            "--input-file",
        ])
        .arg(&plain)
        .arg("--output-file")
        .arg(&cipher)
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let independent = directory.join("independent");
    assert!(
        std::process::Command::new("openssl")
            .args([
                "enc",
                "-aes-128-ecb",
                "-nopad",
                "-K",
                "00112233445566778899aabbccddeeff",
                "-in"
            ])
            .arg(&plain)
            .arg("-out")
            .arg(&independent)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(
        std::fs::read(cipher).unwrap(),
        std::fs::read(independent).unwrap()
    );
    let current = scope(&objects, "wrapping", CryptoMode::Unwrap);
    objects = managed(
        registry.key_operation(
            current,
            profile,
            KeyJob::Unwrap {
                input: output.clone(),
                id: vec![0x80],
                label: b"collision".to_vec(),
            },
        ),
        Some(BackendError::Client(pkcs11_client::ErrorKind::Input)),
    );
    assert!(!objects.iter().any(|entry| entry.label == "collision"));
    let bad = directory.join("bad");
    let mut corrupt = bytes.clone();
    corrupt[0] ^= 1;
    std::fs::write(&bad, corrupt).unwrap();
    let current = scope(&objects, "wrapping", CryptoMode::Unwrap);
    objects = managed(
        registry.key_operation(
            current,
            profile,
            KeyJob::Unwrap {
                input: bad,
                id: vec![0x81],
                label: b"invalid".to_vec(),
            },
        ),
        Some(BackendError::Client(pkcs11_client::ErrorKind::Runtime)),
    );
    assert!(!objects.iter().any(|entry| entry.label == "invalid"));
    for (label, peer, expected) in [
        (
            "derive-p256",
            "02-public.der",
            pkcs11_client::NamedCurve::P256,
        ),
        (
            "derive-p384",
            "03-public.der",
            pkcs11_client::NamedCurve::P384,
        ),
        (
            "derive-p521",
            "04-public.der",
            pkcs11_client::NamedCurve::P521,
        ),
    ] {
        let current = scope(&objects, label, CryptoMode::Derive);
        let profile = match registry.key_options(current).unwrap() {
            BackendResult::KeyOptions { profile, .. } => profile,
            _ => panic!("profile"),
        };
        assert_eq!(
            profile,
            KeyProfile::Classical(KeyOperationProfile::EcdhRaw(expected))
        );
        objects = managed(
            registry.key_operation(
                current,
                profile,
                KeyJob::Derive {
                    peer: fixtures.join(peer),
                    id: vec![0x90],
                    label: b"shared-secret".to_vec(),
                },
            ),
            None,
        );
        let created = object(&objects, "shared-secret", ObjectClass::SECRET_KEY);
        let fields = registry.inspect(module, token, created).unwrap().fields;
        for (name, value) in [
            ("Sensitive", "true"),
            ("Extractable", "false"),
            ("Private", "true"),
            ("Encrypt", "false"),
            ("Decrypt", "false"),
            ("Wrap", "false"),
            ("Unwrap", "false"),
            ("Derive", "true"),
        ] {
            assert!(
                fields
                    .iter()
                    .any(|field| field.name == name && field.value.as_deref() == Some(value)),
                "{name}"
            );
        }
        assert!(fields.iter().any(|field| field.name == "Key bytes"
            && field.value.as_deref()
                == Some(match expected {
                    pkcs11_client::NamedCurve::P256 => "32",
                    pkcs11_client::NamedCurve::P384 => "48",
                    pkcs11_client::NamedCurve::P521 => "66",
                })));
        objects = managed(
            registry.manage(
                module,
                token,
                super::super::ManagementAction::Delete { object: created },
            ),
            None,
        );
    }
    let current = scope(&objects, "derive-p256", CryptoMode::Derive);
    objects = managed(
        registry.key_operation(
            current,
            KeyProfile::Classical(KeyOperationProfile::EcdhRaw(
                pkcs11_client::NamedCurve::P256,
            )),
            KeyJob::Derive {
                peer: fixtures.join("03-public.der"),
                id: vec![0x91],
                label: b"wrong-curve".to_vec(),
            },
        ),
        Some(BackendError::Client(pkcs11_client::ErrorKind::Policy)),
    );
    assert!(!objects.iter().any(|entry| entry.label == "wrong-curve"));
    // Refreshed desktop IDs do not remain valid after a mutating operation.
    assert!(matches!(
        registry.key_options(current),
        Err(BackendError::UnknownObject)
    ));
    registry.logout(module, token).unwrap();
    let current = scope(&objects, "wrapping", CryptoMode::Wrap);
    assert!(matches!(
        registry.key_options(current),
        Err(BackendError::KeyOperationUnavailable)
    ));
    registry.close().unwrap();
    Provider::load(module_path).unwrap().finalize().unwrap();
}
