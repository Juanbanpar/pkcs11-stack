// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{
    AesGcmFiles, BackendResult, CipherJob, CipherParameters, CryptoMode, GenerationKind,
    KeyProfile, LoginRole, ManagementAction, ObjectEntry, ResourceId, SecretInput,
};
use pkcs11_client::{
    AesGcmCapabilities, AesKeySize, Attribute, AttributeType, DigestAlgorithm, MlKemParameterSet,
    ObjectClass,
};
use std::path::PathBuf;

fn managed(result: BackendResult, expected: Option<BackendError>) -> Vec<ObjectEntry> {
    match result {
        BackendResult::Managed {
            error,
            objects: Some(objects),
            ..
        } => {
            assert_eq!(error, expected);
            objects
        }
        other => panic!("unexpected operation result {other:?}"),
    }
}
fn scope(
    module: ResourceId,
    token: ResourceId,
    objects: &[ObjectEntry],
    label: &str,
    mode: CryptoMode,
) -> CryptoScope {
    let class = match mode {
        CryptoMode::Encapsulate => ObjectClass::PUBLIC_KEY,
        CryptoMode::Decapsulate => ObjectClass::PRIVATE_KEY,
        _ => ObjectClass::SECRET_KEY,
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
fn job(output: HkdfOutput, index: u8, case: u8, direction: u8) -> KeyJob {
    KeyJob::Hkdf(HkdfJob {
        output,
        salt: vec![0, 1, 2, 0xFF],
        info: format!("desktop protocol v1 / {case}").into_bytes(),
        id: vec![0xD7, 0x50, 0x58, index, case, direction],
        label: format!("desktop-hkdf-{index}-{case}-{direction}").into_bytes(),
    })
}
fn profile(registry: &Registry, scope: CryptoScope) -> KeyProfile {
    match registry.key_options(scope).unwrap() {
        BackendResult::KeyOptions { profile, .. } => profile,
        _ => panic!("HKDF profile"),
    }
}
#[test]
fn hkdf_invalid_bounds_fail_before_resolving_a_module() {
    let registry = Registry::default();
    let scope = CryptoScope {
        module: ResourceId(1),
        token: ResourceId(2),
        object: ResourceId(3),
        mode: CryptoMode::Hkdf,
    };
    let caps = HkdfCapabilities {
        digest: DigestAlgorithm::Sha256,
        input_length: 32,
    };
    for (salt, info, output) in [
        (vec![0; 4097], Vec::new(), HkdfOutput::Aes256),
        (Vec::new(), vec![0; 4097], HkdfOutput::Aes256),
        (
            Vec::new(),
            Vec::new(),
            HkdfOutput::DerivationSecret { length: 0 },
        ),
        (
            Vec::new(),
            Vec::new(),
            HkdfOutput::DerivationSecret { length: 8161 },
        ),
    ] {
        assert_eq!(
            registry.hkdf_action(
                scope,
                caps,
                KeyJob::Hkdf(HkdfJob {
                    salt,
                    info,
                    output,
                    id: b"id".to_vec(),
                    label: b"label".to_vec()
                })
            ),
            Err(BackendError::HkdfInput)
        );
    }
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh with PKCS11_TEST_DESKTOP=1"]
fn persistent_hkdf_desktop_peer_exchange_output_profiles_and_failures() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap()).join("desktop");
    std::fs::create_dir(&root).unwrap();
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
        .find(|entry| entry.label == "kdf-test")
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
    let mut objects;
    for (index, parameter) in [
        MlKemParameterSet::MlKem512,
        MlKemParameterSet::MlKem768,
        MlKemParameterSet::MlKem1024,
    ]
    .into_iter()
    .enumerate()
    {
        let index = index as u8;
        let recipient = format!("desktop-hkdf-recipient-{index}");
        objects = managed(
            registry.manage(
                module,
                token,
                ManagementAction::Generate {
                    kind: GenerationKind::MlKem(parameter),
                    id: vec![0xD7, 0x50, 0x58, index, 0],
                    label: recipient.as_bytes().to_vec(),
                    always_authenticate: false,
                },
            ),
            None,
        );
        let key = scope(module, token, &objects, &recipient, CryptoMode::Encapsulate);
        let peer_file = root.join(format!("peer-{index}.der"));
        managed(
            registry.manage(
                module,
                token,
                ManagementAction::Export {
                    object: key.object,
                    path: peer_file.clone(),
                },
            ),
            None,
        );
        let peer = format!("desktop-hkdf-peer-{index}");
        objects = managed(
            registry.manage(
                module,
                token,
                ManagementAction::ImportMlKem {
                    path: peer_file,
                    id: vec![0xD7, 0x50, 0x58, index, 1],
                    label: peer.as_bytes().to_vec(),
                },
            ),
            None,
        );
        let cipher_file = root.join(format!("kem-{index}.bin"));
        for (direction, label, mode) in [
            (0, &peer, CryptoMode::Encapsulate),
            (1, &recipient, CryptoMode::Decapsulate),
        ] {
            let scope = scope(module, token, &objects, label, mode);
            let id = vec![0xD7, 0x50, 0x58, index, 2 + direction];
            let label = format!("desktop-hkdf-base-{index}-{direction}").into_bytes();
            let job = if direction == 0 {
                KeyJob::Encapsulate {
                    output: cipher_file.clone(),
                    id,
                    label,
                }
            } else {
                KeyJob::Decapsulate {
                    input: cipher_file.clone(),
                    id,
                    label,
                }
            };
            objects = managed(
                registry.key_operation(scope, KeyProfile::MlKem(parameter), job),
                None,
            );
        }
        for (case, output) in [
            HkdfOutput::Aes128,
            HkdfOutput::Aes192,
            HkdfOutput::Aes256,
            HkdfOutput::DerivationSecret { length: 48 },
            HkdfOutput::DerivationSecret { length: 64 },
        ]
        .into_iter()
        .enumerate()
        {
            let case = case as u8;
            for direction in 0..=1 {
                let base = scope(
                    module,
                    token,
                    &objects,
                    &format!("desktop-hkdf-base-{index}-{direction}"),
                    CryptoMode::Hkdf,
                );
                let selected = profile(&registry, base);
                assert!(matches!(
                    selected,
                    KeyProfile::Hkdf(HkdfCapabilities {
                        digest: DigestAlgorithm::Sha256,
                        input_length: 32
                    })
                ));
                if case == 0 && direction == 0 {
                    let wrong = KeyProfile::Hkdf(HkdfCapabilities {
                        digest: DigestAlgorithm::Sha256,
                        input_length: 64,
                    });
                    objects = managed(
                        registry.key_operation(base, wrong, job(output, index, case, direction)),
                        Some(BackendError::KeyOperationUnavailable),
                    );
                }
                let base = scope(
                    module,
                    token,
                    &objects,
                    &format!("desktop-hkdf-base-{index}-{direction}"),
                    CryptoMode::Hkdf,
                );
                objects = managed(
                    registry.key_operation(base, selected, job(output, index, case, direction)),
                    None,
                );
                assert!(matches!(
                    registry.key_options(base),
                    Err(BackendError::UnknownObject)
                ));
                let base = scope(
                    module,
                    token,
                    &objects,
                    &format!("desktop-hkdf-base-{index}-{direction}"),
                    CryptoMode::Hkdf,
                );
                objects = managed(
                    registry.key_operation(base, selected, job(output, index, case, direction)),
                    Some(BackendError::Client(pkcs11_client::ErrorKind::Input)),
                );
                let derived = scope(
                    module,
                    token,
                    &objects,
                    &format!("desktop-hkdf-{index}-{case}-{direction}"),
                    CryptoMode::Hkdf,
                );
                let reference = registry.reference(module, token, derived.object).unwrap().0;
                let (_, uri) = registry.location(module, token).unwrap();
                read_session(
                    &registry.modules[0],
                    &uri,
                    SessionMode::ReadOnly,
                    |session| {
                        let reads = session
                            .inspect(
                                &reference,
                                &[
                                    AttributeType::Private,
                                    AttributeType::Sensitive,
                                    AttributeType::Extractable,
                                    AttributeType::Encrypt,
                                    AttributeType::Decrypt,
                                    AttributeType::Derive,
                                    AttributeType::ValueLen,
                                ],
                            )
                            .unwrap();
                        let aes = matches!(
                            output,
                            HkdfOutput::Aes128 | HkdfOutput::Aes192 | HkdfOutput::Aes256
                        );
                        for expected in [
                            Attribute::Private(true),
                            Attribute::Sensitive(true),
                            Attribute::Extractable(false),
                            Attribute::Encrypt(aes),
                            Attribute::Decrypt(aes),
                            Attribute::Derive(!aes),
                            Attribute::ValueLen(output.length().try_into().unwrap()),
                        ] {
                            assert!(reads.iter().any(|read| {
                                read.values.as_ref().is_some_and(|values| {
                                    values.expose_values().contains(&expected)
                                })
                            }));
                        }
                        assert!(session.export_value(&reference).is_err());
                        assert!(session.export_public(&reference).is_err());
                        Ok(())
                    },
                )
                .unwrap();
                if let HkdfOutput::DerivationSecret { length } = output {
                    let next = profile(&registry, derived);
                    let digest = if length == 48 {
                        DigestAlgorithm::Sha384
                    } else {
                        DigestAlgorithm::Sha512
                    };
                    assert!(
                        matches!(next, KeyProfile::Hkdf(caps) if caps.digest == digest && caps.input_length == length)
                    );
                    objects = managed(
                        registry.key_operation(
                            derived,
                            next,
                            job(HkdfOutput::Aes256, index, case + 10, direction),
                        ),
                        None,
                    );
                }
            }
            let (aes_case, size) = match output {
                HkdfOutput::Aes128 => (case, AesKeySize::Bits128),
                HkdfOutput::Aes192 => (case, AesKeySize::Bits192),
                HkdfOutput::Aes256 => (case, AesKeySize::Bits256),
                _ => (case + 10, AesKeySize::Bits256),
            };
            let plaintext = root.join(format!("plain-{index}-{case}"));
            let encrypted = root.join(format!("gcm-{index}-{case}"));
            let recovered = root.join(format!("recovered-{index}-{case}"));
            std::fs::write(&plaintext, b"desktop imported peer / KEM / HKDF / GCM").unwrap();
            for (direction, mode, input, output) in [
                (0, CryptoMode::Encrypt, plaintext.clone(), encrypted.clone()),
                (1, CryptoMode::Decrypt, encrypted.clone(), recovered.clone()),
            ] {
                let target = scope(
                    module,
                    token,
                    &objects,
                    &format!("desktop-hkdf-{index}-{aes_case}-{direction}"),
                    mode,
                );
                objects = managed(
                    registry.cipher(
                        target,
                        CipherJob {
                            choice: CipherParameters::AesGcm(AesGcmCapabilities { key_size: size }),
                            aes_gcm: Some(AesGcmFiles {
                                nonce: [0x80 + index; 12],
                                aad: None,
                            }),
                            input,
                            output,
                        },
                    ),
                    None,
                );
            }
            assert_eq!(
                std::fs::read(&recovered).unwrap(),
                std::fs::read(&plaintext).unwrap()
            );
            if case == 0 {
                let base = scope(
                    module,
                    token,
                    &objects,
                    &format!("desktop-hkdf-base-{index}-1"),
                    CryptoMode::Hkdf,
                );
                let selected = profile(&registry, base);
                let KeyJob::Hkdf(mut wrong) = job(HkdfOutput::Aes128, index, 100, 1) else {
                    panic!("HKDF job")
                };
                wrong.info = b"a different public protocol context".to_vec();
                objects = managed(
                    registry.key_operation(base, selected, KeyJob::Hkdf(wrong)),
                    None,
                );
                let wrong_key = scope(
                    module,
                    token,
                    &objects,
                    &format!("desktop-hkdf-{index}-100-1"),
                    CryptoMode::Decrypt,
                );
                let denied = root.join(format!("wrong-context-{index}"));
                objects = managed(
                    registry.cipher(
                        wrong_key,
                        CipherJob {
                            choice: CipherParameters::AesGcm(AesGcmCapabilities {
                                key_size: AesKeySize::Bits128,
                            }),
                            aes_gcm: Some(AesGcmFiles {
                                nonce: [0x80 + index; 12],
                                aad: None,
                            }),
                            input: encrypted.clone(),
                            output: denied.clone(),
                        },
                    ),
                    Some(BackendError::Client(pkcs11_client::ErrorKind::Runtime)),
                );
                assert_eq!(std::fs::metadata(denied).unwrap().len(), 0);
            }
        }
        let base = scope(
            module,
            token,
            &objects,
            &format!("desktop-hkdf-base-{index}-0"),
            CryptoMode::Hkdf,
        );
        registry.logout(module, token).unwrap();
        managed(
            registry.key_operation(
                base,
                KeyProfile::Hkdf(HkdfCapabilities {
                    digest: DigestAlgorithm::Sha256,
                    input_length: 32,
                }),
                job(HkdfOutput::Aes128, index, 99, 0),
            ),
            Some(BackendError::KeyOperationUnavailable),
        );
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
}
