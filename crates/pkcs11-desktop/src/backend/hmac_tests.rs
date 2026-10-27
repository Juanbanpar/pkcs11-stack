// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{
    BackendResult, GenerationKind, KeyProfile, LoginRole, ManagementAction, ObjectEntry,
    SecretInput,
};
use pkcs11_client::{HmacAlgorithm, HmacCapabilities};
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
    let choices = registry.capabilities(module, token).unwrap();
    for (index, algorithm) in HmacAlgorithm::ALL.into_iter().enumerate() {
        if !choices.contains(&GenerationKind::Hmac(algorithm)) {
            continue;
        }
        let label = format!("desktop-{algorithm}");
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
        let tag = root.join(format!("tag-{algorithm}"));
        let denied = root.join(format!("denied-{algorithm}"));
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
                        pkcs11_client::HmacOptions {
                            full: Some(HmacCapabilities {
                                key_length: 1,
                                sha256: index == 0,
                                sha384: index == 1,
                                sha512: index == 2,
                                sha224: index == 3,
                                sha512_224: index == 4,
                                sha512_256: index == 5,
                                sha3_224: index == 6,
                                sha3_256: index == 7,
                                sha3_384: index == 8,
                                sha3_512: index == 9,
                            }),
                            general: None
                        },
                        KeyJob::Hmac {
                            profile: pkcs11_client::HmacTagProfile::Full,
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
                        profile: pkcs11_client::HmacTagProfile::Full,
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
                        pkcs11_client::HmacOptions {
                            full: Some(HmacCapabilities {
                                key_length: algorithm.tag_length(),
                                sha256: index == 0,
                                sha384: index == 1,
                                sha512: index == 2,
                                sha224: index == 3,
                                sha512_224: index == 4,
                                sha512_256: index == 5,
                                sha3_224: index == 6,
                                sha3_256: index == 7,
                                sha3_384: index == 8,
                                sha3_512: index == 9,
                            }),
                            general: None
                        },
                        KeyJob::Hmac {
                            profile: pkcs11_client::HmacTagProfile::Full,
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

#[test]
#[ignore = "requires disposable Kryoptic runner after runtime HMAC fixtures"]
fn persistent_hmac_general_desktop_files_and_stale_profiles() {
    use pkcs11_client::HmacTagProfile;
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap())
        .join("desktop-hmac-general");
    std::fs::create_dir(&root).unwrap();
    let message = root.join("message");
    std::fs::write(&message, b"desktop general").unwrap();
    let mut registry = Registry::default();
    let module = registry
        .load(&PathBuf::from(
            std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap(),
        ))
        .unwrap();
    let token = registry.modules[0]
        .entry
        .tokens
        .iter()
        .find(|t| t.label == "kdf-test")
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
    let objects = registry.objects(module, token).unwrap();
    for (index, algorithm) in HmacAlgorithm::ALL.into_iter().enumerate() {
        let label = format!("hmac-vector-{index}-false-{}", algorithm.tag_length());
        for tag_length in [algorithm.tag_length() / 2, algorithm.tag_length()] {
            let tag_profile = HmacTagProfile::General { tag_length };
            let tag = root.join(format!("tag-{index}-{tag_length}"));
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
                let BackendResult::KeyOptions {
                    profile: KeyProfile::Hmac(options),
                    ..
                } = registry.key_options(scope).unwrap()
                else {
                    panic!("HMAC options")
                };
                if mode == CryptoMode::Hmac {
                    let denied = root.join(format!("denied-{index}-{tag_length}"));
                    let mut stale = options;
                    stale.general.as_mut().unwrap().key_length = 1;
                    assert_eq!(
                        registry.hmac_action(
                            scope,
                            stale,
                            KeyJob::Hmac {
                                algorithm,
                                profile: tag_profile,
                                input: message.clone(),
                                tag: denied.clone()
                            }
                        ),
                        Err(BackendError::KeyOperationUnavailable)
                    );
                    assert!(!denied.exists());
                }
                if expected == Some(BackendError::MacMismatch) {
                    std::fs::write(&tag, vec![0; tag_length]).unwrap();
                }
                if expected == Some(BackendError::MacInput) {
                    std::fs::write(&tag, vec![0; tag_length - 1]).unwrap();
                }
                assert_eq!(
                    registry.hmac_action(
                        scope,
                        options,
                        KeyJob::Hmac {
                            algorithm,
                            profile: tag_profile,
                            input: message.clone(),
                            tag: tag.clone(),
                        },
                    ),
                    expected.map_or(Ok(()), Err),
                );
                if mode == CryptoMode::Hmac {
                    assert_eq!(std::fs::read(&tag).unwrap().len(), tag_length);
                    let before = std::fs::read(&tag).unwrap();
                    assert_eq!(
                        registry.hmac_action(
                            scope,
                            options,
                            KeyJob::Hmac {
                                algorithm,
                                profile: tag_profile,
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
    }
    registry.close().unwrap();
}
