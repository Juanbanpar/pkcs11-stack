// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{
    BackendResult, GenerationKind, LoginRole, ManagementAction, ObjectEntry, SecretInput,
};
use pkcs11_client::HmacAlgorithm;
use std::path::PathBuf;
fn managed(result: BackendResult, expected: Option<BackendError>) -> Vec<ObjectEntry> {
    let BackendResult::Managed {
        error,
        objects: Some(objects),
        ..
    } = result
    else {
        panic!("managed result")
    };
    assert_eq!(error, expected);
    objects
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn software_token_hmac_generation_verification_files_and_stale_profiles() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root =
        PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap()).join("desktop-hmac");
    std::fs::create_dir(&root).unwrap();
    let message = root.join("message");
    std::fs::write(&message, b"desktop MAC input").unwrap();
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
    for (index, algorithm) in HmacAlgorithm::ALL.into_iter().enumerate() {
        let label = format!("desktop-hmac-{}", algorithm.tag_length());
        let mut objects = managed(
            registry.manage(
                module,
                token,
                ManagementAction::Generate {
                    kind: GenerationKind::Hmac(algorithm),
                    id: label.as_bytes().to_vec(),
                    label: label.as_bytes().to_vec(),
                    always_authenticate: false,
                },
            ),
            None,
        );
        let tag = root.join(format!("tag-{}", algorithm.tag_length()));
        let denied = root.join(format!("denied-{}", algorithm.tag_length()));
        for (mode, expected) in [
            (CryptoMode::Hmac, None),
            (CryptoMode::VerifyHmac, None),
            (CryptoMode::VerifyHmac, Some(BackendError::MacMismatch)),
            (CryptoMode::VerifyHmac, Some(BackendError::MacInput)),
        ] {
            let scope = CryptoScope {
                module,
                token,
                object: objects.iter().find(|o| o.label == label).unwrap().id,
                mode,
            };
            let BackendResult::KeyOptions { profile, .. } = registry.key_options(scope).unwrap()
            else {
                panic!("MAC profile")
            };
            if mode == CryptoMode::Hmac {
                assert_eq!(
                    registry.hmac_action(
                        scope,
                        HmacCapabilities {
                            key_length: 1,
                            sha256: index == 0,
                            sha384: index == 1,
                            sha512: index == 2
                        },
                        KeyJob::Hmac {
                            algorithm,
                            input: message.clone(),
                            tag: denied.clone()
                        }
                    ),
                    Err(BackendError::KeyOperationUnavailable)
                );
                assert!(!denied.exists());
            }
            if expected == Some(BackendError::MacMismatch) {
                std::fs::write(&tag, vec![0; algorithm.tag_length()]).unwrap();
            }
            if expected == Some(BackendError::MacInput) {
                std::fs::write(&tag, vec![0; algorithm.tag_length() - 1]).unwrap();
            }
            objects = managed(
                registry.key_operation(
                    scope,
                    profile,
                    KeyJob::Hmac {
                        algorithm,
                        input: message.clone(),
                        tag: tag.clone(),
                    },
                ),
                expected,
            );
            if mode == CryptoMode::Hmac {
                assert_eq!(std::fs::read(&tag).unwrap().len(), algorithm.tag_length());
                assert!(matches!(
                    registry.key_options(scope),
                    Err(BackendError::UnknownObject)
                ));
                let scope = CryptoScope {
                    object: objects.iter().find(|o| o.label == label).unwrap().id,
                    ..scope
                };
                let before = std::fs::read(&tag).unwrap();
                assert_eq!(
                    registry.hmac_action(
                        scope,
                        HmacCapabilities {
                            key_length: algorithm.tag_length(),
                            sha256: index == 0,
                            sha384: index == 1,
                            sha512: index == 2
                        },
                        KeyJob::Hmac {
                            algorithm,
                            input: message.clone(),
                            tag: tag.clone()
                        }
                    ),
                    Err(BackendError::FileWrite)
                );
                assert_eq!(std::fs::read(&tag).unwrap(), before);
            }
        }
    }
    registry.close().unwrap();
}
