// SPDX-License-Identifier: MIT OR Apache-2.0
use super::tests::{choices, managed, scope};
use super::*;
use crate::backend::{GenerationKind, LoginRole, ManagementAction};
use pkcs11_client::{Authentication, MlDsaVerifyingKey, PublicKeyRef, SessionMode};

fn job(
    parameter: MlDsaParameterSet,
    input: &Path,
    output: &Path,
    domain_context: &[u8],
    pin: bool,
) -> CryptoJob {
    CryptoJob {
        parameters: SignatureProfile::MlDsa(parameter),
        software_hashing: false,
        domain_context: domain_context.to_vec(),
        input: input.into(),
        signature: output.into(),
        context: pin.then(|| SecretInput::Value("12345678".into())),
    }
}

#[test]
#[ignore = "requires tools/test-softhsm.sh; ML-DSA execution required with PKCS11_TEST_REQUIRE_PQC=1"]
fn software_token_ml_dsa_signing_context_authentication_and_output_contracts() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap())
        .join("desktop-ml-dsa-sign");
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
        .find(|entry| entry.label == "client-test")
        .unwrap()
        .id;
    let parameters: Vec<_> = registry
        .capabilities(module, token)
        .unwrap()
        .into_iter()
        .filter_map(|kind| match kind {
            GenerationKind::MlDsa(parameter) => Some(parameter),
            _ => None,
        })
        .collect();
    if std::env::var("PKCS11_TEST_REQUIRE_PQC").as_deref() == Ok("1") {
        assert_eq!(
            parameters,
            [
                MlDsaParameterSet::MlDsa44,
                MlDsaParameterSet::MlDsa65,
                MlDsaParameterSet::MlDsa87
            ]
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
    for (index, &parameter) in parameters.iter().enumerate() {
        let label = format!("desktop-ml-dsa-sign-{index}");
        let always = index == 1;
        let mut objects = managed(
            registry.manage(
                module,
                token,
                ManagementAction::Generate {
                    kind: GenerationKind::MlDsa(parameter),
                    id: vec![0xD7, 0x50, 0x53, index as u8],
                    label: label.as_bytes().to_vec(),
                    always_authenticate: always,
                },
            ),
            None,
        );
        let target = scope(module, token, &objects, &label, CryptoMode::Sign);
        assert_eq!(
            registry
                .inspect(module, token, target.object)
                .unwrap()
                .key_type,
            Some(KeyType::ML_DSA)
        );
        let (options, context) = choices(&registry, target, false);
        assert_eq!(
            options,
            vec![SignatureOption {
                parameters: SignatureProfile::MlDsa(parameter),
                plan: None
            }]
        );
        assert_eq!(context, always);
        assert!(matches!(
            registry.crypto_options(target, true),
            Err(BackendError::SignatureChoice)
        ));
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
        let der = session.export_public(key.as_object_ref()).unwrap();
        session.close().unwrap();
        let verifier = MlDsaVerifyingKey::from_spki_der(&der).unwrap();
        let message: &[u8] = if index == 0 {
            b""
        } else {
            b"desktop pure ML-DSA message"
        };
        let domain = if index == 1 {
            vec![b'x'; 255]
        } else {
            Vec::new()
        };
        let input = root.join(format!("message-{index}"));
        std::fs::write(&input, message).unwrap();
        let bad_context = root.join(format!("context-too-long-{index}"));
        objects = managed(
            registry
                .crypto(
                    target,
                    job(parameter, &input, &bad_context, &[0; 256], always),
                )
                .unwrap(),
            Some(BackendError::MlDsaContext),
        );
        assert!(!bad_context.exists());
        let wrong = root.join(format!("wrong-parameter-{index}"));
        let other = parameters[(index + 1) % parameters.len()];
        objects = managed(
            registry
                .crypto(
                    scope(module, token, &objects, &label, CryptoMode::Sign),
                    job(other, &input, &wrong, &domain, always),
                )
                .unwrap(),
            Some(BackendError::SignatureChoice),
        );
        assert!(!wrong.exists());
        let wrong_family = root.join(format!("wrong-family-{index}"));
        let mut request = job(parameter, &input, &wrong_family, &[], always);
        request.parameters = SignatureProfile::Classical(SignatureParameters {
            algorithm: pkcs11_client::SignatureAlgorithm::RsaPkcs1,
            digest: pkcs11_client::DigestAlgorithm::Sha256,
            pss: None,
        });
        objects = managed(
            registry
                .crypto(
                    scope(module, token, &objects, &label, CryptoMode::Sign),
                    request,
                )
                .unwrap(),
            Some(BackendError::SignatureChoice),
        );
        assert!(!wrong_family.exists());
        let protected = root.join(format!("unsupported-protected-path-{index}"));
        let mut request = job(parameter, &input, &protected, &domain, always);
        request.context = Some(SecretInput::ProtectedPath);
        objects = managed(
            registry
                .crypto(
                    scope(module, token, &objects, &label, CryptoMode::Sign),
                    request,
                )
                .unwrap(),
            Some(BackendError::AuthenticationUnavailable),
        );
        assert!(!protected.exists());
        let forbidden = root.join(format!("hashing-{index}"));
        let mut request = job(parameter, &input, &forbidden, &domain, always);
        request.software_hashing = true;
        objects = managed(
            registry
                .crypto(
                    scope(module, token, &objects, &label, CryptoMode::Sign),
                    request,
                )
                .unwrap(),
            Some(BackendError::SignatureChoice),
        );
        assert!(!forbidden.exists());
        if always {
            let missing = root.join("missing-pin");
            objects = managed(
                registry
                    .crypto(
                        scope(module, token, &objects, &label, CryptoMode::Sign),
                        job(parameter, &input, &missing, &domain, false),
                    )
                    .unwrap(),
                Some(BackendError::ContextRequired),
            );
            assert!(!missing.exists());
            let failed = root.join("incorrect-pin");
            let mut request = job(parameter, &input, &failed, &domain, true);
            request.context = Some(SecretInput::Value("context-secret-canary".into()));
            let result = registry
                .crypto(
                    scope(module, token, &objects, &label, CryptoMode::Sign),
                    request,
                )
                .unwrap();
            assert!(!format!("{result:?}").contains("context-secret-canary"));
            objects = managed(
                result,
                Some(BackendError::Client(pkcs11_client::ErrorKind::Runtime)),
            );
            assert_eq!(std::fs::metadata(failed).unwrap().len(), 0);
        }
        let output = root.join(format!("signature-{index}"));
        let target = scope(module, token, &objects, &label, CryptoMode::Sign);
        objects = managed(
            registry
                .crypto(target, job(parameter, &input, &output, &domain, always))
                .unwrap(),
            None,
        );
        assert!(matches!(
            registry.crypto_options(target, false),
            Err(BackendError::UnknownObject)
        ));
        let signature = std::fs::read(&output).unwrap();
        assert_eq!(signature.len(), parameter.signature_length());
        let request = MlDsaRequest {
            parameter_set: parameter,
            message,
            context: &domain,
            hedging: MlDsaHedging::Required,
        };
        verifier.verify_signature(&request, &signature).unwrap();
        assert!(
            verifier
                .verify_signature(
                    &MlDsaRequest {
                        context: b"different",
                        ..request
                    },
                    &signature
                )
                .is_err()
        );
        assert!(
            verifier
                .verify_signature(
                    &MlDsaRequest {
                        message: b"different",
                        ..request
                    },
                    &signature
                )
                .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        objects = managed(
            registry
                .crypto(
                    scope(module, token, &objects, &label, CryptoMode::Sign),
                    job(parameter, &input, &output, &domain, always),
                )
                .unwrap(),
            Some(BackendError::FileWrite),
        );
        assert_eq!(std::fs::read(&output).unwrap(), signature);
        let target = scope(module, token, &objects, &label, CryptoMode::Sign);
        registry.logout(module, token).unwrap();
        let denied = root.join(format!("logged-out-{index}"));
        managed(
            registry
                .crypto(target, job(parameter, &input, &denied, &domain, always))
                .unwrap(),
            Some(BackendError::SigningUnavailable),
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
