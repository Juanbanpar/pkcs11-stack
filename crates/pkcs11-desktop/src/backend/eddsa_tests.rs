// SPDX-License-Identifier: MIT OR Apache-2.0
use super::tests::{choices, managed};
use super::*;
use crate::backend::{GenerationKind, LoginRole, ManagementAction};
use pkcs11_client::{Authentication, EdDsaVerifyingKey, SessionMode};

fn scope(
    module: ResourceId,
    token: ResourceId,
    objects: &[crate::backend::ObjectEntry],
    label: &str,
    mode: CryptoMode,
) -> CryptoScope {
    let class = if mode == CryptoMode::Sign {
        ObjectClass::PRIVATE_KEY
    } else {
        ObjectClass::PUBLIC_KEY
    };
    CryptoScope {
        module,
        token,
        mode,
        object: objects
            .iter()
            .find(|entry| entry.label == label && entry.class == Some(class))
            .unwrap()
            .id,
    }
}

fn job(curve: EdDsaCurve, input: &Path, signature: &Path, always: bool) -> CryptoJob {
    CryptoJob {
        parameters: SignatureProfile::EdDsa(curve),
        software_hashing: false,
        domain_context: Vec::new(),
        input: input.into(),
        signature: signature.into(),
        context: always.then(|| SecretInput::Value("12345678".into())),
    }
}
#[test]
fn eddsa_certificate_file_verification_rejects_hashing_contexts_and_wrong_curves() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkcs11-client/tests/fixtures/eddsa");
    for (curve, name) in [
        (EdDsaCurve::Ed25519, "ed25519"),
        (EdDsaCurve::Ed448, "ed448"),
    ] {
        let certificate = VerificationCertificate::from_der(
            std::fs::read(root.join(format!("{name}.der"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            certificate.options(),
            vec![SignatureOption {
                parameters: SignatureProfile::EdDsa(curve),
                plan: None
            }]
        );
        let request = || {
            job(
                curve,
                &root.join("message.txt"),
                &root.join(format!("{name}.sig")),
                false,
            )
        };
        certificate.verify(request()).unwrap();
        let mut bad = request();
        bad.software_hashing = true;
        assert_eq!(certificate.verify(bad), Err(BackendError::SignatureChoice));
        let mut bad = request();
        bad.domain_context = vec![1];
        assert_eq!(certificate.verify(bad), Err(BackendError::SignatureChoice));
        let mut bad = request();
        bad.parameters = SignatureProfile::EdDsa(if curve == EdDsaCurve::Ed25519 {
            EdDsaCurve::Ed448
        } else {
            EdDsaCurve::Ed25519
        });
        assert_eq!(certificate.verify(bad), Err(BackendError::SignatureChoice));
    }
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn eddsa_desktop_generation_signing_public_import_and_native_verification() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    if std::env::var("PKCS11_TEST_REQUIRE_EDDSA").as_deref() != Ok("1") {
        return;
    }
    let root =
        PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap()).join("desktop-eddsa");
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
        .find(|token| token.label == "client-test")
        .unwrap()
        .id;
    let generation = registry.capabilities(module, token).unwrap();
    for curve in [EdDsaCurve::Ed25519, EdDsaCurve::Ed448] {
        assert!(generation.contains(&GenerationKind::EdDsa(curve)));
    }
    registry
        .login(
            module,
            token,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();
    for (index, curve) in [EdDsaCurve::Ed25519, EdDsaCurve::Ed448]
        .into_iter()
        .enumerate()
    {
        let label = format!("desktop-{curve:?}");
        let always = index == 1;
        let mut objects = managed(
            registry.manage(
                module,
                token,
                ManagementAction::Generate {
                    kind: GenerationKind::EdDsa(curve),
                    id: vec![0xD7, 0xED, 0xD0, index as u8],
                    label: label.as_bytes().to_vec(),
                    always_authenticate: always,
                },
            ),
            None,
        );
        let target = scope(module, token, &objects, &label, CryptoMode::Sign);
        let (options, context) = choices(&registry, target, false);
        assert_eq!(
            options,
            vec![SignatureOption {
                parameters: SignatureProfile::EdDsa(curve),
                plan: None
            }]
        );
        assert_eq!(context, always);
        assert!(matches!(
            registry.crypto_options(target, true),
            Err(BackendError::SignatureChoice)
        ));
        let input = root.join(format!("{index}.message"));
        std::fs::write(
            &input,
            if index == 0 {
                &b""[..]
            } else {
                &b"desktop EdDSA original message"[..]
            },
        )
        .unwrap();
        let signature = root.join(format!("{index}.sig"));
        objects = managed(
            registry
                .crypto(target, job(curve, &input, &signature, always))
                .unwrap(),
            None,
        );
        let target = scope(module, token, &objects, &label, CryptoMode::Verify);
        let (options, _) = choices(&registry, target, false);
        assert_eq!(options[0].parameters, SignatureProfile::EdDsa(curve));
        assert!(matches!(
            registry.crypto(target, job(curve, &input, &signature, false)),
            Ok(BackendResult::Verified { .. })
        ));
        let (reference, _) = registry.reference(module, token, target.object).unwrap();
        let (_, uri) = registry.location(module, token).unwrap();
        let mut session = registry.modules[0]
            .provider
            .management(&uri, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        let der = session.export_public(&reference).unwrap();
        session.close().unwrap();
        let verifier = EdDsaVerifyingKey::from_spki_der(&der).unwrap();
        verifier
            .verify_signature(
                &EdDsaRequest {
                    curve,
                    message: &std::fs::read(&input).unwrap(),
                },
                &std::fs::read(&signature).unwrap(),
            )
            .unwrap();
        let spki = root.join(format!("{index}.spki"));
        std::fs::write(&spki, der).unwrap();
        let imported = format!("import-{label}");
        objects = managed(
            registry.manage(
                module,
                token,
                ManagementAction::ImportPublicKey {
                    path: spki,
                    id: vec![0xD7, 0xED, 0xD1, index as u8],
                    label: imported.as_bytes().to_vec(),
                    purpose: pkcs11_client::ClassicalPublicKeyPurpose::Verification,
                },
            ),
            None,
        );
        let target = scope(module, token, &objects, &imported, CryptoMode::Verify);
        assert!(matches!(
            registry.crypto(target, job(curve, &input, &signature, false)),
            Ok(BackendResult::Verified { .. })
        ));
        let target = scope(module, token, &objects, &label, CryptoMode::Sign);
        let forbidden = root.join(format!("{index}.forbidden"));
        let mut request = job(curve, &input, &forbidden, always);
        request.domain_context = vec![1];
        objects = managed(
            registry.crypto(target, request).unwrap(),
            Some(BackendError::SignatureChoice),
        );
        assert!(!forbidden.exists());
        assert!(!objects.is_empty());
    }
}
