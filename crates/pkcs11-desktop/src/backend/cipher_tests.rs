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
        BackendResult::CipherOptions { choices, .. } => choices,
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
    assert!(matches!(
        registry.cipher_options(CryptoScope {
            object: restricted,
            mode: CryptoMode::Decrypt,
            ..encrypt
        }),
        Err(BackendError::Client(pkcs11_client::ErrorKind::Policy))
    ));
    let mut supported = 0;
    for choice in choices {
        let digest = match choice.digest {
            DigestAlgorithm::Sha256 => "sha256",
            DigestAlgorithm::Sha384 => "sha384",
            DigestAlgorithm::Sha512 => "sha512",
        };
        let ciphertext = directory.join(format!("cipher-{digest}"));
        let current = scope(module, token, &objects, CryptoMode::Encrypt);
        let result = registry.cipher(
            current,
            CipherJob {
                choice,
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
                    choice,
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
                    choice,
                    input: independent_cipher,
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
                    choice,
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
                    choice,
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
                    choice,
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
