// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{BackendCommand, BackendEvent, LoginRole, ObjectEntry, RequestId};
use pkcs11_client::{DigestAlgorithm, SignatureAlgorithm};

#[test]
fn crypto_file_limits_and_unknown_targets_report_fixed_errors() {
    let path = std::env::temp_dir().join(format!("desktop-crypto-limit-{}", std::process::id()));
    std::fs::write(&path, b"redaction-canary").unwrap();
    assert_eq!(read_bounded(&path, 4), Err(BackendError::CryptoRead));
    assert_eq!(read_bounded(&path, 16).unwrap(), b"redaction-canary");
    std::fs::remove_file(&path).unwrap();
    assert_eq!(read_bounded(&path, 16), Err(BackendError::CryptoRead));
    let mut registry = Registry::default();
    let event = registry.execute(BackendCommand::CryptoOptions {
        id: RequestId(1),
        scope: CryptoScope {
            module: ResourceId(1),
            token: ResourceId(2),
            object: ResourceId(3),
            mode: CryptoMode::Verify,
        },
        software_hashing: false,
    });
    assert!(matches!(
        event,
        BackendEvent::Completed {
            id: RequestId(1),
            result: Err(BackendError::UnknownModule)
        }
    ));
    assert!(!format!("{event:?}").contains("canary"));
}
pub(super) fn scope(
    module: ResourceId,
    token: ResourceId,
    objects: &[ObjectEntry],
    label: &str,
    mode: CryptoMode,
) -> CryptoScope {
    let class = if mode == CryptoMode::Sign {
        ObjectClass::PRIVATE_KEY
    } else {
        ObjectClass::CERTIFICATE
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
pub(super) fn choices(
    registry: &Registry,
    scope: CryptoScope,
    software: bool,
) -> (Vec<SignatureOption>, bool) {
    match registry.crypto_options(scope, software).unwrap() {
        BackendResult::CryptoOptions {
            options, context, ..
        } => (options, context),
        _ => panic!("unexpected signing choices result"),
    }
}
fn job(
    parameters: SignatureProfile,
    input: &Path,
    signature: &Path,
    context: Option<SecretInput>,
) -> CryptoJob {
    CryptoJob {
        parameters,
        software_hashing: true,
        domain_context: Vec::new(),
        input: input.into(),
        signature: signature.into(),
        context,
    }
}
pub(super) fn managed(result: BackendResult, expected: Option<BackendError>) -> Vec<ObjectEntry> {
    match result {
        BackendResult::Managed {
            objects: Some(objects),
            error,
            ..
        } => {
            assert_eq!(error, expected);
            objects
        }
        _ => panic!("unexpected signing result"),
    }
}
// Independent conversion for OpenSSL, which expects ASN.1 ECDSA signatures.
fn ecdsa_der(raw: &[u8]) -> Vec<u8> {
    fn integer(raw: &[u8]) -> Vec<u8> {
        let first = raw
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(raw.len() - 1);
        let mut bytes = raw[first..].to_vec();
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        let mut result = vec![2, bytes.len() as u8];
        result.extend(bytes);
        result
    }
    let mut body = integer(&raw[..raw.len() / 2]);
    body.extend(integer(&raw[raw.len() / 2..]));
    let mut result = vec![0x30];
    if body.len() >= 128 {
        result.push(0x81);
    }
    result.push(body.len() as u8);
    result.extend(body);
    result
}
#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn software_token_signing_verification_context_and_file_failures() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let directory =
        std::env::temp_dir().join(format!("desktop-crypto-integration-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let input = directory.join("message");
    std::fs::write(&input, b"desktop signing regression").unwrap();
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
    let mut objects = registry.objects(module, token).unwrap();
    let public = scope(module, token, &objects, "rsa", CryptoMode::Verify);
    assert!(!choices(&registry, public, false).0.is_empty());
    assert!(matches!(
        registry.crypto_options(
            CryptoScope {
                mode: CryptoMode::Sign,
                ..public
            },
            false
        ),
        Err(BackendError::SigningUnavailable)
    ));
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
    let fixtures = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let mut sequence = 0;
    for (label, id) in [
        ("rsa", "01"),
        ("p256", "02"),
        ("p384", "03"),
        ("p521", "04"),
    ] {
        let initial = scope(module, token, &objects, label, CryptoMode::Sign);
        let (options, context) = choices(&registry, initial, true);
        assert!(!options.is_empty());
        assert!(!context);
        for option in options {
            sequence += 1;
            let output = directory.join(format!("signature-{sequence}"));
            let target = scope(module, token, &objects, label, CryptoMode::Sign);
            objects = managed(
                registry
                    .crypto(target, job(option.parameters, &input, &output, None))
                    .unwrap(),
                None,
            );
            assert!(matches!(
                registry.crypto_options(target, true),
                Err(BackendError::UnknownObject)
            ));
            let certificate = scope(module, token, &objects, label, CryptoMode::Verify);
            assert!(matches!(
                registry.crypto(certificate, job(option.parameters, &input, &output, None)),
                Ok(BackendResult::Verified { .. })
            ));
            let raw = std::fs::read(&output).unwrap();
            let independent = directory.join("openssl-signature");
            std::fs::write(
                &independent,
                if matches!(option.parameters, SignatureProfile::Classical(p) if p.algorithm == SignatureAlgorithm::Ecdsa) {
                    ecdsa_der(&raw)
                } else {
                    raw.clone()
                },
            )
            .unwrap();
            let SignatureProfile::Classical(parameters) = option.parameters else {
                panic!("classical choices")
            };
            let digest = match parameters.digest {
                DigestAlgorithm::Sha256 => "sha256",
                DigestAlgorithm::Sha384 => "sha384",
                DigestAlgorithm::Sha512 => "sha512",
            };
            let mut command = std::process::Command::new("openssl");
            command
                .arg("dgst")
                .arg(format!("-{digest}"))
                .arg("-verify")
                .arg(fixtures.join(format!("{id}-public.pem")))
                .arg("-signature")
                .arg(&independent);
            if let Some(pss) = parameters.pss {
                command.args([
                    "-sigopt",
                    "rsa_padding_mode:pss",
                    "-sigopt",
                    &format!("rsa_pss_saltlen:{}", pss.salt_len),
                    "-sigopt",
                    &format!("rsa_mgf1_md:{digest}"),
                ]);
            }
            assert!(command.arg(&input).output().unwrap().status.success());
            let bad = directory.join("bad-signature");
            let mut tampered = raw.clone();
            tampered[0] ^= 1;
            std::fs::write(&bad, &tampered).unwrap();
            assert!(matches!(
                registry.crypto(certificate, job(option.parameters, &input, &bad, None)),
                Err(BackendError::SignatureMismatch)
            ));
            let target = scope(module, token, &objects, label, CryptoMode::Sign);
            objects = managed(
                registry
                    .crypto(target, job(option.parameters, &input, &output, None))
                    .unwrap(),
                Some(BackendError::FileWrite),
            );
            assert_eq!(std::fs::read(&output).unwrap(), raw);
        }
    }
    for _ in 0..2 {
        objects = managed(
            registry.manage(
                module,
                token,
                crate::backend::ManagementAction::Generate {
                    kind: crate::backend::GenerationKind::Signing(pkcs11_client::KeyKind::Ec(
                        pkcs11_client::NamedCurve::P256,
                    )),
                    id: vec![0xE8],
                    label: b"desktop-ambiguous".to_vec(),
                    always_authenticate: false,
                },
            ),
            None,
        );
    }
    let duplicate = scope(
        module,
        token,
        &objects,
        "desktop-ambiguous",
        CryptoMode::Sign,
    );
    assert!(matches!(
        registry.crypto_options(duplicate, true),
        Err(BackendError::AmbiguousObject)
    ));
    let always = scope(module, token, &objects, "always", CryptoMode::Sign);
    let (options, context) = choices(&registry, always, false);
    assert!(context);
    assert!(!options.is_empty());
    let parameters = options[0].parameters;
    let missing = directory.join("no-context");
    objects = managed(
        registry
            .crypto(always, job(parameters, &input, &missing, None))
            .unwrap(),
        Some(BackendError::ContextRequired),
    );
    assert!(!missing.exists());
    let target = scope(module, token, &objects, "always", CryptoMode::Sign);
    let protected = directory.join("unsupported-protected-path");
    objects = managed(
        registry
            .crypto(
                target,
                job(
                    parameters,
                    &input,
                    &protected,
                    Some(SecretInput::ProtectedPath),
                ),
            )
            .unwrap(),
        Some(BackendError::AuthenticationUnavailable),
    );
    assert!(!protected.exists());
    let target = scope(module, token, &objects, "always", CryptoMode::Sign);
    let wrong = directory.join("wrong-pin");
    objects = managed(
        registry
            .crypto(
                target,
                job(
                    parameters,
                    &input,
                    &wrong,
                    Some(SecretInput::Value("wrong-canary".into())),
                ),
            )
            .unwrap(),
        Some(BackendError::Client(pkcs11_client::ErrorKind::Runtime)),
    );
    assert!(std::fs::read(&wrong).unwrap().is_empty());
    let target = scope(module, token, &objects, "always", CryptoMode::Sign);
    let correct = directory.join("context-signature");
    objects = managed(
        registry
            .crypto(
                target,
                job(
                    parameters,
                    &input,
                    &correct,
                    Some(SecretInput::Value("12345678".into())),
                ),
            )
            .unwrap(),
        None,
    );
    let certificate = scope(module, token, &objects, "always", CryptoMode::Verify);
    registry
        .crypto(certificate, job(parameters, &input, &correct, None))
        .unwrap();
    let saved = std::fs::read(&correct).unwrap();
    let target = scope(module, token, &objects, "always", CryptoMode::Sign);
    managed(
        registry
            .crypto(
                target,
                job(
                    parameters,
                    &input,
                    &correct,
                    Some(SecretInput::Value("wrong-canary".into())),
                ),
            )
            .unwrap(),
        Some(BackendError::FileWrite),
    );
    assert_eq!(std::fs::read(&correct).unwrap(), saved);
    registry.logout(module, token).unwrap();
    objects = registry.objects(module, token).unwrap();
    let certificate = scope(module, token, &objects, "always", CryptoMode::Verify);
    registry
        .crypto(certificate, job(parameters, &input, &correct, None))
        .unwrap();
    std::fs::write(&input, b"changed message").unwrap();
    assert!(matches!(
        registry.crypto(certificate, job(parameters, &input, &correct, None)),
        Err(BackendError::SignatureMismatch)
    ));
    registry.close().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
