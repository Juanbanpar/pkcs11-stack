// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{
    BackendCommand, BackendEvent, LoginRole, ObjectEntry, RequestId, SecretInput,
};
use pkcs11_client::{DigestAlgorithm, ObjectClass, Provider};
fn scope(
    module: super::super::ResourceId,
    token: super::super::ResourceId,
    objects: &[ObjectEntry],
    mode: CryptoMode,
) -> CryptoScope {
    let class = if mode == CryptoMode::Encrypt {
        ObjectClass::PUBLIC_KEY
    } else {
        ObjectClass::PRIVATE_KEY
    };
    CryptoScope {
        module,
        token,
        object: objects
            .iter()
            .find(|entry| entry.label == "cipher" && entry.class == Some(class))
            .unwrap()
            .id,
        mode,
    }
}
fn managed(result: BackendResult, expected: Option<BackendError>) -> Vec<ObjectEntry> {
    match result {
        BackendResult::Managed {
            objects: Some(objects),
            error,
            ..
        } => {
            assert_eq!(error, expected);
            objects
        }
        other => panic!("unexpected result: {other:?}"),
    }
}
fn command(args: &[&str]) {
    assert!(
        std::process::Command::new("openssl")
            .args(args)
            .output()
            .unwrap()
            .status
            .success()
    );
}
#[test]
#[ignore = "requires the isolated SHA-2 OAEP SoftHSM runner"]
fn software_token_oaep_explicit_parameters_and_validation_before_output() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    if std::env::var("PKCS11_TEST_REQUIRE_RSA_OAEP_SHA2").as_deref() != Ok("1") {
        return;
    }
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
        .find(|t| t.label == "client-test")
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
    let current = scope(module, token, &objects, CryptoMode::Encrypt);
    let choice = match registry.cipher_options(current).unwrap() {
        BackendResult::CipherOptions { choices, .. } => choices
            .into_iter()
            .find(|c| matches!(c, CipherParameters::Oaep(c) if c.digest == DigestAlgorithm::Sha256))
            .unwrap(),
        _ => panic!("OAEP options"),
    };
    let input = root.join("desktop-oaep-explicit-message");
    let cipher = root.join("desktop-oaep-explicit-cipher");
    let plain = root.join("desktop-oaep-explicit-plain");
    std::fs::write(&input, b"desktop explicit OAEP").unwrap();
    let job = |input, output, label| CipherJob {
        choice,
        context: None,
        aes_gcm: None,
        oaep: Some(OaepSettings {
            mgf_digest: DigestAlgorithm::Sha512,
            label,
        }),
        input,
        output,
    };
    objects = managed(
        registry.cipher(
            current,
            job(input.clone(), cipher.clone(), vec![0, 255, 1, 35]),
        ),
        None,
    );
    command(&[
        "pkeyutl",
        "-decrypt",
        "-inkey",
        root.join("cipher.key").to_str().unwrap(),
        "-in",
        cipher.to_str().unwrap(),
        "-out",
        plain.to_str().unwrap(),
        "-pkeyopt",
        "rsa_padding_mode:oaep",
        "-pkeyopt",
        "rsa_oaep_md:sha256",
        "-pkeyopt",
        "rsa_mgf1_md:sha512",
        "-pkeyopt",
        "rsa_oaep_label:00ff0123",
    ]);
    assert_eq!(
        std::fs::read(&plain).unwrap(),
        std::fs::read(&input).unwrap()
    );
    command(&[
        "pkeyutl",
        "-encrypt",
        "-pubin",
        "-keyform",
        "DER",
        "-inkey",
        root.join("cipher-public.der").to_str().unwrap(),
        "-in",
        input.to_str().unwrap(),
        "-out",
        cipher.to_str().unwrap(),
        "-pkeyopt",
        "rsa_padding_mode:oaep",
        "-pkeyopt",
        "rsa_oaep_md:sha256",
        "-pkeyopt",
        "rsa_mgf1_md:sha512",
        "-pkeyopt",
        "rsa_oaep_label:00ff0123",
    ]);
    std::fs::remove_file(&plain).unwrap();
    let current = scope(module, token, &objects, CryptoMode::Decrypt);
    objects = managed(
        registry.cipher(
            current,
            job(cipher.clone(), plain.clone(), vec![0, 255, 1, 35]),
        ),
        None,
    );
    assert_eq!(
        std::fs::read(&plain).unwrap(),
        std::fs::read(&input).unwrap()
    );
    let rejected = root.join("desktop-oaep-explicit-rejected");
    let current = scope(module, token, &objects, CryptoMode::Encrypt);
    objects = managed(
        registry.cipher(current, job(input, rejected.clone(), vec![0; 4097])),
        Some(BackendError::CipherInput),
    );
    assert!(!rejected.exists());
    let current = scope(module, token, &objects, CryptoMode::Decrypt);
    managed(
        registry.cipher(current, job(cipher, rejected.clone(), vec![0, 255, 1, 36])),
        Some(BackendError::Client(pkcs11_client::ErrorKind::Runtime)),
    );
    assert!(std::fs::read(&rejected).unwrap().is_empty());
    registry.close().unwrap();
}
#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn software_token_oaep_interoperability_permissions_and_file_failures() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let fixtures = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let directory = fixtures.join("desktop-cipher");
    std::fs::create_dir(&directory).unwrap();
    let input = directory.join("input");
    std::fs::write(&input, b"OAEP secret redaction canary").unwrap();
    let path = PathBuf::from(std::env::var_os("PKCS11_TEST_MODULE").unwrap());
    let mut registry = Registry::default();
    let module = registry.load(&path).unwrap();
    let token = registry.modules[0]
        .entry
        .tokens
        .iter()
        .find(|entry| entry.label == "client-test")
        .unwrap()
        .id;
    let mut objects = registry.objects(module, token).unwrap();
    let encrypt = scope(module, token, &objects, CryptoMode::Encrypt);
    let choices = match registry.cipher_options(encrypt).unwrap() {
        BackendResult::CipherOptions { choices, .. } => choices
            .into_iter()
            .map(|choice| match choice {
                CipherParameters::Oaep(choice) => choice,
                _ => panic!("OAEP choice"),
            })
            .collect::<Vec<_>>(),
        _ => panic!("choices"),
    };
    assert_eq!(choices.len(), 3);
    assert_eq!(choices[0].maximum_plaintext, 190);
    let event = registry.execute(BackendCommand::Login {
        id: RequestId(1),
        module,
        token,
        role: LoginRole::User,
        pin: SecretInput::Value("12345678".into()),
    });
    assert!(matches!(
        event,
        BackendEvent::Completed {
            result: Ok(BackendResult::Modules { error: None, .. }),
            ..
        }
    ));
    objects = registry.objects(module, token).unwrap();
    let restricted = objects
        .iter()
        .find(|entry| {
            entry.label == "cipher-always" && entry.class == Some(ObjectClass::PRIVATE_KEY)
        })
        .unwrap()
        .id;
    let auth_choices = match registry
        .cipher_options(CryptoScope {
            object: restricted,
            mode: CryptoMode::Decrypt,
            ..encrypt
        })
        .unwrap()
    {
        BackendResult::CipherOptions { choices, .. } => choices,
        _ => panic!("OAEP choices"),
    };
    assert!(auth_choices.iter().all(
        |choice| matches!(choice, CipherParameters::Oaep(choice) if choice.always_authenticate)
    ));
    let mut supported = 0;
    for choice in choices {
        let digest = match choice.digest {
            DigestAlgorithm::Sha224 => "sha224",
            DigestAlgorithm::Sha3_224 => "sha3-224",
            DigestAlgorithm::Sha3_256 => "sha3-256",
            DigestAlgorithm::Sha3_384 => "sha3-384",
            DigestAlgorithm::Sha3_512 => "sha3-512",
            DigestAlgorithm::Sha256 => "sha256",
            DigestAlgorithm::Sha384 => "sha384",
            DigestAlgorithm::Sha512 => "sha512",
        };
        let ciphertext = directory.join(format!("cipher-{digest}"));
        let current = scope(module, token, &objects, CryptoMode::Encrypt);
        let result = registry.cipher(
            current,
            CipherJob {
                oaep: None,
                context: None,
                aes_gcm: None,
                choice: CipherParameters::Oaep(choice),
                input: input.clone(),
                output: ciphertext.clone(),
            },
        );
        match result {
            BackendResult::Managed {
                objects: Some(updated),
                error: Some(error),
                ..
            } => {
                assert_eq!(error, BackendError::OaepParametersRejected);
                assert!(std::fs::read(&ciphertext).unwrap().is_empty());
                objects = updated;
                assert_ne!(
                    std::env::var("PKCS11_TEST_REQUIRE_RSA_OAEP_SHA2").as_deref(),
                    Ok("1"),
                    "required SHA-2 OAEP failed"
                );
                // Older packaged SoftHSM rejects SHA-2 OAEP initialization.
                continue;
            }
            result => objects = managed(result, None),
        }
        supported += 1;
        assert_eq!(
            std::fs::read(&ciphertext).unwrap().len(),
            choice.ciphertext_length
        );
        let independent = directory.join("openssl-plain");
        command(&[
            "pkeyutl",
            "-decrypt",
            "-inkey",
            fixtures.join("cipher.key").to_str().unwrap(),
            "-in",
            ciphertext.to_str().unwrap(),
            "-out",
            independent.to_str().unwrap(),
            "-pkeyopt",
            "rsa_padding_mode:oaep",
            "-pkeyopt",
            &format!("rsa_oaep_md:{digest}"),
            "-pkeyopt",
            &format!("rsa_mgf1_md:{digest}"),
        ]);
        assert_eq!(
            std::fs::read(&independent).unwrap(),
            std::fs::read(&input).unwrap()
        );
        let decrypted = directory.join(format!("plain-{digest}"));
        let target = scope(module, token, &objects, CryptoMode::Decrypt);
        objects = managed(
            registry.cipher(
                target,
                CipherJob {
                    oaep: None,
                    context: None,
                    aes_gcm: None,
                    choice: CipherParameters::Oaep(choice),
                    input: ciphertext.clone(),
                    output: decrypted.clone(),
                },
            ),
            None,
        );
        assert_eq!(
            std::fs::read(&decrypted).unwrap(),
            std::fs::read(&input).unwrap()
        );
        let independent_cipher = directory.join("openssl-cipher");
        command(&[
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-keyform",
            "DER",
            "-inkey",
            fixtures.join("cipher-public.der").to_str().unwrap(),
            "-in",
            input.to_str().unwrap(),
            "-out",
            independent_cipher.to_str().unwrap(),
            "-pkeyopt",
            "rsa_padding_mode:oaep",
            "-pkeyopt",
            &format!("rsa_oaep_md:{digest}"),
            "-pkeyopt",
            &format!("rsa_mgf1_md:{digest}"),
        ]);
        let output = directory.join(format!("interop-{digest}"));
        let target = scope(module, token, &objects, CryptoMode::Decrypt);
        objects = managed(
            registry.cipher(
                target,
                CipherJob {
                    oaep: None,
                    context: None,
                    aes_gcm: None,
                    choice: CipherParameters::Oaep(choice),
                    input: independent_cipher.clone(),
                    output: output.clone(),
                },
            ),
            None,
        );
        assert_eq!(
            std::fs::read(&output).unwrap(),
            std::fs::read(&input).unwrap()
        );

        let auth_scope = CryptoScope {
            module,
            token,
            mode: CryptoMode::Decrypt,
            object: objects
                .iter()
                .find(|object| {
                    object.label == "cipher-always"
                        && object.class == Some(ObjectClass::PRIVATE_KEY)
                })
                .unwrap()
                .id,
        };
        let auth_choice = CipherParameters::Oaep(OaepChoice {
            always_authenticate: true,
            ..choice
        });
        let missing = directory.join(format!("missing-context-{digest}"));
        objects = managed(
            registry.cipher(
                auth_scope,
                CipherJob {
                    oaep: None,
                    context: None,
                    aes_gcm: None,
                    choice: auth_choice,
                    input: independent_cipher.clone(),
                    output: missing.clone(),
                },
            ),
            Some(BackendError::Client(pkcs11_client::ErrorKind::Policy)),
        );
        assert_eq!(std::fs::metadata(&missing).unwrap().len(), 0);
        let auth_scope = CryptoScope {
            object: objects
                .iter()
                .find(|object| {
                    object.label == "cipher-always"
                        && object.class == Some(ObjectClass::PRIVATE_KEY)
                })
                .unwrap()
                .id,
            ..auth_scope
        };
        let output = directory.join(format!("context-plain-{digest}"));
        objects = managed(
            registry.cipher(
                auth_scope,
                CipherJob {
                    oaep: None,
                    context: Some(SecretInput::Value("12345678".into())),
                    aes_gcm: None,
                    choice: auth_choice,
                    input: independent_cipher.clone(),
                    output: output.clone(),
                },
            ),
            None,
        );
        assert_eq!(
            std::fs::read(&output).unwrap(),
            std::fs::read(&input).unwrap()
        );
        let saved = std::fs::read(&decrypted).unwrap();
        let target = scope(module, token, &objects, CryptoMode::Decrypt);
        objects = managed(
            registry.cipher(
                target,
                CipherJob {
                    oaep: None,
                    context: None,
                    aes_gcm: None,
                    choice: CipherParameters::Oaep(choice),
                    input: ciphertext.clone(),
                    output: decrypted.clone(),
                },
            ),
            Some(BackendError::FileWrite),
        );
        assert_eq!(std::fs::read(&decrypted).unwrap(), saved);
        let bad = directory.join("bad");
        std::fs::write(&bad, vec![0; choice.ciphertext_length]).unwrap();
        let target = scope(module, token, &objects, CryptoMode::Decrypt);
        let failed = directory.join(format!("invalid-{digest}"));
        objects = managed(
            registry.cipher(
                target,
                CipherJob {
                    oaep: None,
                    context: None,
                    aes_gcm: None,
                    choice: CipherParameters::Oaep(choice),
                    input: bad,
                    output: failed.clone(),
                },
            ),
            Some(BackendError::Client(pkcs11_client::ErrorKind::Runtime)),
        );
        assert!(std::fs::read(failed).unwrap().is_empty());
        let too_large = directory.join("oversized");
        std::fs::write(&too_large, vec![1; choice.maximum_plaintext + 1]).unwrap();
        let target = scope(module, token, &objects, CryptoMode::Encrypt);
        let rejected = directory.join("rejected");
        objects = managed(
            registry.cipher(
                target,
                CipherJob {
                    oaep: None,
                    context: None,
                    aes_gcm: None,
                    choice: CipherParameters::Oaep(choice),
                    input: too_large,
                    output: rejected.clone(),
                },
            ),
            Some(BackendError::CipherInput),
        );
        assert!(!rejected.exists());
    }
    if std::env::var("PKCS11_TEST_REQUIRE_RSA_OAEP_SHA2").as_deref() == Ok("1") {
        assert_eq!(supported, 3);
    }
    registry.close().unwrap();
    let provider = Provider::load(path).unwrap();
    provider.finalize().unwrap();
}
