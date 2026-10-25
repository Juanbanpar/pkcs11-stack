// SPDX-License-Identifier: MIT OR Apache-2.0
use super::tests::{choices, managed, scope};
use super::*;
use crate::backend::{BackendCommand, BackendEvent, LoginRole, ManagementAction, RequestId};

const PARAMETERS: [(MlDsaParameterSet, &str); 3] = [
    (MlDsaParameterSet::MlDsa44, "mldsa44"),
    (MlDsaParameterSet::MlDsa65, "mldsa65"),
    (MlDsaParameterSet::MlDsa87, "mldsa87"),
];
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../pkcs11-client/tests/fixtures")
        .join(name)
}
fn job(parameter: MlDsaParameterSet, name: &str, contextual: bool) -> CryptoJob {
    CryptoJob {
        parameters: SignatureProfile::MlDsa(parameter),
        software_hashing: false,
        domain_context: if contextual {
            b"fixture-context".to_vec()
        } else {
            Vec::new()
        },
        input: fixture("message.txt"),
        signature: fixture(&format!(
            "{name}.{}",
            if contextual { "context.sig" } else { "sig" }
        )),
        context: None,
    }
}
#[test]
fn certificate_dispatch_and_ml_dsa_file_verification_are_provider_free() {
    let directory = std::env::temp_dir().join(format!(
        "desktop-ml-dsa-verification-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let altered_message = directory.join("message");
    let altered_signature = directory.join("signature");
    std::fs::write(&altered_message, b"changed message").unwrap();
    for (parameter, name) in PARAMETERS {
        let certificate = VerificationCertificate::from_der(
            std::fs::read(fixture(&format!("{name}.der"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            certificate.options(),
            vec![SignatureOption {
                parameters: SignatureProfile::MlDsa(parameter),
                plan: None
            }]
        );
        for contextual in [false, true] {
            certificate
                .verify(job(parameter, name, contextual))
                .unwrap();
            let mut changed = job(parameter, name, contextual);
            changed.domain_context = b"different context".to_vec();
            assert_eq!(
                certificate.verify(changed),
                Err(BackendError::SignatureMismatch)
            );
            let mut changed = job(parameter, name, contextual);
            changed.input = altered_message.clone();
            assert_eq!(
                certificate.verify(changed),
                Err(BackendError::SignatureMismatch)
            );
            let mut bytes = std::fs::read(job(parameter, name, contextual).signature).unwrap();
            bytes[0] ^= 1;
            for signature in [&bytes[..], &bytes[..bytes.len() - 1]] {
                std::fs::write(&altered_signature, signature).unwrap();
                let mut changed = job(parameter, name, contextual);
                changed.signature = altered_signature.clone();
                assert_eq!(
                    certificate.verify(changed),
                    Err(BackendError::SignatureMismatch)
                );
                assert_eq!(std::fs::read(&altered_signature).unwrap(), signature);
            }
            let mut changed = job(parameter, name, contextual);
            changed.input = fixture("message.txt").with_extension("missing");
            assert_eq!(certificate.verify(changed), Err(BackendError::CryptoRead));
            let mut changed = job(parameter, name, contextual);
            changed.signature = fixture("message.txt");
            assert_eq!(
                certificate.verify(changed),
                Err(BackendError::SignatureMismatch)
            );
        }
        let mut wrong = job(parameter, name, false);
        wrong.parameters = SignatureProfile::MlDsa(if parameter == MlDsaParameterSet::MlDsa44 {
            MlDsaParameterSet::MlDsa65
        } else {
            MlDsaParameterSet::MlDsa44
        });
        wrong.input = "absent".into();
        assert_eq!(
            certificate.verify(wrong),
            Err(BackendError::SignatureChoice)
        );
        for (domain, expected) in [
            (vec![0; 255], BackendError::SignatureMismatch),
            (vec![0; 256], BackendError::MlDsaContext),
        ] {
            let mut request = job(parameter, name, false);
            request.domain_context = domain;
            assert_eq!(certificate.verify(request), Err(expected));
        }
        let mut forbidden = job(parameter, name, false);
        forbidden.software_hashing = true;
        assert_eq!(
            certificate.verify(forbidden),
            Err(BackendError::SignatureChoice)
        );
        let mut forbidden = job(parameter, name, false);
        forbidden.context = Some(SecretInput::Value("verification-secret-canary".into()));
        assert_eq!(
            certificate.verify(forbidden),
            Err(BackendError::SignatureChoice)
        );
        let mut trailing = std::fs::read(fixture(&format!("{name}.der"))).unwrap();
        trailing.push(0);
        assert!(VerificationCertificate::from_der(trailing).is_err());
    }
    for name in ["rsa", "p256", "p384", "p521"] {
        let certificate = VerificationCertificate::from_der(
            std::fs::read(fixture(&format!("{name}.der"))).unwrap(),
        )
        .unwrap();
        assert!(
            certificate
                .options()
                .iter()
                .all(|option| matches!(option.parameters, SignatureProfile::Classical(_)))
        );
        assert_eq!(
            certificate.verify(job(MlDsaParameterSet::MlDsa44, "mldsa44", false)),
            Err(BackendError::SignatureChoice)
        );
    }
    assert!(VerificationCertificate::from_der(vec![1, 2, 3]).is_err());
    assert!(
        VerificationCertificate::from_der(std::fs::read(fixture("ed25519.der")).unwrap()).is_err()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn software_token_ml_dsa_certificates_verify_without_login_or_token_mechanisms() {
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
    registry
        .login(
            module,
            token,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();
    for (index, (_, name)) in PARAMETERS.into_iter().enumerate() {
        managed(
            registry.manage(
                module,
                token,
                ManagementAction::ImportCertificate {
                    path: fixture(&format!("{name}.der")),
                    id: vec![0xD7, 0x50, 0x54, index as u8],
                    label: format!("desktop-ml-dsa-verify-{index}").into_bytes(),
                },
            ),
            None,
        );
    }
    registry.logout(module, token).unwrap();
    let objects = registry.objects(module, token).unwrap();
    for (index, (parameter, name)) in PARAMETERS.into_iter().enumerate() {
        let target = scope(
            module,
            token,
            &objects,
            &format!("desktop-ml-dsa-verify-{index}"),
            CryptoMode::Verify,
        );
        let (options, authentication) = choices(&registry, target, false);
        assert!(!authentication);
        assert_eq!(
            options,
            vec![SignatureOption {
                parameters: SignatureProfile::MlDsa(parameter),
                plan: None
            }]
        );
        for contextual in [false, true] {
            let request = job(parameter, name, contextual);
            let message = std::fs::read(&request.input).unwrap();
            let signature = std::fs::read(&request.signature).unwrap();
            assert!(
                matches!(registry.crypto(target, request), Ok(BackendResult::Verified { scope }) if scope == target)
            );
            assert_eq!(std::fs::read(fixture("message.txt")).unwrap(), message);
            assert_eq!(
                std::fs::read(job(parameter, name, contextual).signature).unwrap(),
                signature
            );
        }
        let mut changed = job(parameter, name, true);
        changed.domain_context.clear();
        let event = registry.execute(BackendCommand::Crypto {
            id: RequestId(700 + index as u64),
            scope: target,
            job: changed,
        });
        assert!(
            matches!(event, BackendEvent::Completed { id: RequestId(id), result: Err(BackendError::SignatureMismatch) } if id == 700 + index as u64)
        );
    }
    let stale = scope(
        module,
        token,
        &objects,
        "desktop-ml-dsa-verify-0",
        CryptoMode::Verify,
    );
    registry.objects(module, token).unwrap();
    assert!(matches!(
        registry.crypto(stale, job(MlDsaParameterSet::MlDsa44, "mldsa44", false)),
        Err(BackendError::UnknownObject)
    ));
    registry.close().unwrap();
}
