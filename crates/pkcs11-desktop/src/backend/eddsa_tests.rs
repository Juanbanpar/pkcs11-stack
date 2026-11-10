// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../pkcs11-client/tests/fixtures/eddsa")
        .join(name)
}

fn job(curve: EdDsaCurve, signature: &str) -> CryptoJob {
    CryptoJob {
        parameters: SignatureProfile::EdDsa(curve),
        software_hashing: false,
        domain_context: Vec::new(),
        input: fixture("message.txt"),
        signature: fixture(signature),
        context: None,
    }
}

#[test]
fn eddsa_certificate_file_verification_rejects_hashing_contexts_and_wrong_curves() {
    for (curve, name) in [
        (EdDsaCurve::Ed25519, "ed25519"),
        (EdDsaCurve::Ed448, "ed448"),
    ] {
        let certificate = VerificationCertificate::from_der(
            std::fs::read(fixture(&format!("{name}.der"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            certificate.options(),
            vec![SignatureOption {
                parameters: SignatureProfile::EdDsa(curve),
                plan: None
            }]
        );
        certificate
            .verify(job(curve, &format!("{name}.sig")))
            .unwrap();

        let mut bad = job(curve, &format!("{name}.sig"));
        bad.software_hashing = true;
        assert_eq!(certificate.verify(bad), Err(BackendError::SignatureChoice));

        let mut bad = job(curve, &format!("{name}.sig"));
        bad.domain_context = vec![1];
        assert_eq!(certificate.verify(bad), Err(BackendError::SignatureChoice));

        let mut bad = job(curve, &format!("{name}.sig"));
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
fn eddsa_desktop_generation_signing_and_native_verification() {
    use super::tests::{choices, managed};
    use crate::backend::{GenerationKind, LoginRole, ManagementAction, ObjectEntry};
    use pkcs11_client::{Authentication, EdDsaVerifyingKey, PublicKeyRef, SessionMode};

    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
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
        assert!(!GenerationKind::EdDsa(curve).supports_context_authentication());
        assert_eq!(
            GenerationKind::EdDsa(curve).validate(b"id", b"label", true),
            Err(BackendError::InvalidForm)
        );
    }
    registry
        .login(
            module,
            token,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();

    let target_for = |objects: &[ObjectEntry], label: &str, mode: CryptoMode| {
        super::tests::scope(module, token, objects, label, mode)
    };
    for (index, curve) in [EdDsaCurve::Ed25519, EdDsaCurve::Ed448]
        .into_iter()
        .enumerate()
    {
        let label = format!("desktop-{curve:?}");
        let mut objects = managed(
            registry.manage(
                module,
                token,
                ManagementAction::Generate {
                    kind: GenerationKind::EdDsa(curve),
                    id: vec![0xD7, 0xED, 0xD0, index as u8],
                    label: label.as_bytes().to_vec(),
                    always_authenticate: false,
                },
            ),
            None,
        );
        let target = target_for(&objects, &label, CryptoMode::Sign);
        let (options, context) = choices(&registry, target, false);
        assert_eq!(
            options,
            vec![SignatureOption {
                parameters: SignatureProfile::EdDsa(curve),
                plan: None
            }]
        );
        assert!(!context);
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
        let request = CryptoJob {
            parameters: SignatureProfile::EdDsa(curve),
            software_hashing: false,
            domain_context: Vec::new(),
            input: input.clone(),
            signature: signature.clone(),
            context: None,
        };
        objects = managed(registry.crypto(target, request).unwrap(), None);

        let public = objects
            .iter()
            .find(|entry| entry.label == label && entry.class == Some(ObjectClass::PUBLIC_KEY))
            .unwrap()
            .id;
        let (reference, _) = registry.reference(module, token, public).unwrap();
        let key = PublicKeyRef::new(reference.uri().to_string().parse().unwrap()).unwrap();
        let (_, uri) = registry.location(module, token).unwrap();
        let mut session = registry.modules[0]
            .provider
            .management(&uri, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        let der = session.export_eddsa_public_key(&key).unwrap();
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

        let target = target_for(&objects, &label, CryptoMode::Sign);
        let forbidden = root.join(format!("{index}.forbidden"));
        let request = CryptoJob {
            parameters: SignatureProfile::EdDsa(curve),
            software_hashing: false,
            domain_context: vec![1],
            input: input.clone(),
            signature: forbidden.clone(),
            context: None,
        };
        objects = managed(
            registry.crypto(target, request).unwrap(),
            Some(BackendError::SignatureChoice),
        );
        assert!(!forbidden.exists());
        assert!(!objects.is_empty());
    }
}
