// SPDX-License-Identifier: MIT OR Apache-2.0
use super::tests::{choices, managed};
use super::*;
use crate::backend::{
    BackendResult, GenerationKind, KeyJob, KeyProfile, LoginRole, ManagementAction,
    MontgomeryKdfChoice, MontgomeryOutputChoice, ObjectEntry,
};
use pkcs11_client::{
    AesGcmDecryptRequest, AesGcmEncryptRequest, Authentication, HashInput, HashMlDsaRequest,
    HashSlhDsaRequest, MlDsaHedging, MlDsaParameterSet, ObjectRef, Pin, PrehashAlgorithm,
    PublicKeyRef, SessionMode, SigningPolicy, SlhDsaHedging, SlhDsaParameterSet,
};
use secrecy::ExposeSecret;

fn job(parameters: SignatureProfile, input: &Path, signature: &Path, context: &[u8]) -> CryptoJob {
    CryptoJob {
        parameters,
        software_hashing: false,
        domain_context: context.to_vec(),
        input: input.into(),
        signature: signature.into(),
        context: None,
    }
}

fn verify_scope(
    module: ResourceId,
    token: ResourceId,
    objects: &[ObjectEntry],
    label: &str,
) -> CryptoScope {
    CryptoScope {
        module,
        token,
        mode: CryptoMode::Verify,
        object: objects
            .iter()
            .find(|entry| entry.label == label && entry.class == Some(ObjectClass::PUBLIC_KEY))
            .unwrap()
            .id,
    }
}

fn key_scope(
    module: ResourceId,
    token: ResourceId,
    objects: &[ObjectEntry],
    label: &str,
) -> CryptoScope {
    CryptoScope {
        module,
        token,
        mode: CryptoMode::Derive,
        object: objects
            .iter()
            .find(|entry| entry.label == label && entry.class == Some(ObjectClass::PRIVATE_KEY))
            .unwrap()
            .id,
    }
}

fn openssl_verify(root: &Path, public: &[u8], message: &[u8], signature: &[u8]) {
    let openssl = std::env::var_os("PKCS11_TEST_PQC_OPENSSL").unwrap_or_else(|| "openssl".into());
    let key = root.join("slh-public.der");
    let input = root.join("slh-message");
    let signature_path = root.join("slh-signature");
    std::fs::write(&key, public).unwrap();
    std::fs::write(&input, message).unwrap();
    std::fs::write(&signature_path, signature).unwrap();
    let output = std::process::Command::new(openssl)
        .args([
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            key.to_str().unwrap(),
            "-keyform",
            "DER",
            "-rawin",
            "-in",
            input.to_str().unwrap(),
            "-sigfile",
            signature_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "OpenSSL SLH-DSA verification failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires tools/test-pqc-kryoptic.sh disposable store"]
fn slh_and_hash_pqc_desktop_signing() {
    assert_eq!(
        std::env::var("PKCS11_TEST_PQC_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_PQC_DIR").unwrap()).join("desktop-pqc");
    std::fs::create_dir(&root).unwrap();
    let mut registry = Registry::default();
    let module = registry
        .load(&PathBuf::from(
            std::env::var_os("PKCS11_TEST_PQC_MODULE").unwrap(),
        ))
        .unwrap();
    let token = registry.modules[0]
        .entry
        .tokens
        .iter()
        .find(|token| token.label == "pqc-test")
        .unwrap()
        .id;
    let capabilities = registry.capabilities(module, token).unwrap();
    assert!(capabilities.contains(&GenerationKind::SlhDsa(SlhDsaParameterSet::Sha2_128F)));
    assert!(capabilities.contains(&GenerationKind::HashSlhDsa(SlhDsaParameterSet::Sha2_128F)));
    registry
        .login(
            module,
            token,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();

    let target_for = |objects: &[ObjectEntry], label: &str| {
        super::tests::scope(module, token, objects, label, CryptoMode::Sign)
    };
    let parameter = SlhDsaParameterSet::Sha2_128F;
    let mut objects = managed(
        registry.manage(
            module,
            token,
            ManagementAction::Generate {
                kind: GenerationKind::SlhDsa(parameter),
                id: b"desktop-slh".to_vec(),
                label: b"desktop-slh".to_vec(),
                always_authenticate: false,
            },
        ),
        None,
    );
    let target = target_for(&objects, "desktop-slh");
    let (options, _) = choices(&registry, target, false);
    assert_eq!(
        options,
        vec![SignatureOption {
            parameters: SignatureProfile::SlhDsa(parameter),
            plan: None
        }]
    );
    let message = root.join("slh-message");
    std::fs::write(&message, b"desktop pure SLH-DSA message").unwrap();
    let signature = root.join("slh-signature");
    objects = managed(
        registry
            .crypto(
                target,
                job(
                    SignatureProfile::SlhDsa(parameter),
                    &message,
                    &signature,
                    b"",
                ),
            )
            .unwrap(),
        None,
    );
    let public = objects
        .iter()
        .find(|entry| entry.label == "desktop-slh" && entry.class == Some(ObjectClass::PUBLIC_KEY))
        .unwrap()
        .id;
    let (reference, _) = registry.reference(module, token, public).unwrap();
    let public_key = PublicKeyRef::new(reference.uri().to_string().parse().unwrap()).unwrap();
    let (_, uri) = registry.location(module, token).unwrap();
    let mut session = registry.modules[0]
        .provider
        .management(&uri, SessionMode::ReadOnly, Authentication::None)
        .unwrap();
    let spki = session.export_slh_dsa_public_key(&public_key).unwrap();
    session.close().unwrap();
    openssl_verify(
        &root,
        &spki,
        &std::fs::read(&message).unwrap(),
        &std::fs::read(&signature).unwrap(),
    );
    let verify_target = verify_scope(module, token, &objects, "desktop-slh");
    let (verify_options, _) = choices(&registry, verify_target, false);
    assert!(
        verify_options
            .iter()
            .any(|option| { option.parameters == SignatureProfile::SlhDsa(parameter) })
    );
    let result = registry.crypto(
        verify_target,
        job(
            SignatureProfile::SlhDsa(parameter),
            &message,
            &signature,
            b"",
        ),
    );
    assert!(
        matches!(result, Ok(BackendResult::Verified { .. })),
        "{result:?}"
    );

    let mut objects = managed(
        registry.manage(
            module,
            token,
            ManagementAction::Generate {
                kind: GenerationKind::HashSlhDsa(parameter),
                id: b"desktop-hash-slh".to_vec(),
                label: b"desktop-hash-slh".to_vec(),
                always_authenticate: false,
            },
        ),
        None,
    );
    let target = target_for(&objects, "desktop-hash-slh");
    let (options, _) = choices(&registry, target, false);
    assert!(
        options
            .iter()
            .all(|option| matches!(option.parameters, SignatureProfile::HashSlhDsa { .. }))
    );
    assert!(!options.is_empty());
    let message = root.join("hash-slh-message");
    std::fs::write(&message, b"desktop HashSLH-DSA message").unwrap();
    let signature = root.join("hash-slh-signature");
    let profile = SignatureProfile::HashSlhDsa {
        parameter_set: parameter,
        hash: PrehashAlgorithm::Sha256,
        prehashed: false,
    };
    assert!(options.iter().any(|option| option.parameters == profile));
    objects = managed(
        registry
            .crypto(
                target,
                job(profile, &message, &signature, b"desktop-context"),
            )
            .unwrap(),
        None,
    );
    let public = objects
        .iter()
        .find(|entry| {
            entry.label == "desktop-hash-slh" && entry.class == Some(ObjectClass::PUBLIC_KEY)
        })
        .unwrap()
        .id;
    let (reference, _) = registry.reference(module, token, public).unwrap();
    let public_key = PublicKeyRef::new(reference.uri().to_string().parse().unwrap()).unwrap();
    let client = registry.modules[0]
        .provider
        .client(
            &uri,
            std::num::NonZeroUsize::new(1).unwrap(),
            SigningPolicy::default(),
        )
        .unwrap();
    let pin = secrecy::SecretString::from("12345678");
    client
        .verify_hash_slh_dsa(
            &public_key,
            &HashSlhDsaRequest {
                parameter_set: parameter,
                input: HashInput::Message {
                    hash: PrehashAlgorithm::Sha256,
                    message: &std::fs::read(&message).unwrap(),
                },
                context: b"desktop-context",
                hedging: SlhDsaHedging::Deterministic,
            },
            &std::fs::read(&signature).unwrap(),
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    client.close().unwrap();
    let verify_target = verify_scope(module, token, &objects, "desktop-hash-slh");
    let (verify_options, _) = choices(&registry, verify_target, false);
    assert!(verify_options.iter().any(|option| {
        option.parameters
            == SignatureProfile::HashSlhDsa {
                parameter_set: parameter,
                hash: PrehashAlgorithm::Sha256,
                prehashed: false,
            }
    }));
    assert!(matches!(
        registry.crypto(
            verify_target,
            job(
                SignatureProfile::HashSlhDsa {
                    parameter_set: parameter,
                    hash: PrehashAlgorithm::Sha256,
                    prehashed: false,
                },
                &message,
                &signature,
                b"desktop-context"
            )
        ),
        Ok(BackendResult::Verified { .. })
    ));

    let mut objects = managed(
        registry.manage(
            module,
            token,
            ManagementAction::Generate {
                kind: GenerationKind::MlDsa(MlDsaParameterSet::MlDsa44),
                id: b"desktop-hash-ml".to_vec(),
                label: b"desktop-hash-ml".to_vec(),
                always_authenticate: false,
            },
        ),
        None,
    );
    let target = target_for(&objects, "desktop-hash-ml");
    let (options, _) = choices(&registry, target, false);
    assert!(
        options
            .iter()
            .any(|option| matches!(option.parameters, SignatureProfile::HashMlDsa { .. }))
    );
    let message = root.join("hash-ml-message");
    std::fs::write(&message, b"desktop HashML-DSA message").unwrap();
    let signature = root.join("hash-ml-signature");
    let profile = SignatureProfile::HashMlDsa {
        parameter_set: MlDsaParameterSet::MlDsa44,
        hash: PrehashAlgorithm::Sha256,
        prehashed: false,
    };
    assert!(options.iter().any(|option| option.parameters == profile));
    objects = managed(
        registry
            .crypto(
                target,
                job(profile, &message, &signature, b"desktop-ml-context"),
            )
            .unwrap(),
        None,
    );
    let public = objects
        .iter()
        .find(|entry| {
            entry.label == "desktop-hash-ml" && entry.class == Some(ObjectClass::PUBLIC_KEY)
        })
        .unwrap()
        .id;
    let (reference, _) = registry.reference(module, token, public).unwrap();
    let public_key = PublicKeyRef::new(reference.uri().to_string().parse().unwrap()).unwrap();
    let client = registry.modules[0]
        .provider
        .client(
            &uri,
            std::num::NonZeroUsize::new(1).unwrap(),
            SigningPolicy::default(),
        )
        .unwrap();
    client
        .verify_hash_ml_dsa(
            &public_key,
            &HashMlDsaRequest {
                parameter_set: MlDsaParameterSet::MlDsa44,
                input: HashInput::Message {
                    hash: PrehashAlgorithm::Sha256,
                    message: &std::fs::read(&message).unwrap(),
                },
                context: b"desktop-ml-context",
                hedging: MlDsaHedging::Deterministic,
            },
            &std::fs::read(&signature).unwrap(),
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    client.close().unwrap();
    let verify_target = verify_scope(module, token, &objects, "desktop-hash-ml");
    let (verify_options, _) = choices(&registry, verify_target, false);
    assert!(verify_options.iter().any(|option| {
        option.parameters
            == SignatureProfile::HashMlDsa {
                parameter_set: MlDsaParameterSet::MlDsa44,
                hash: PrehashAlgorithm::Sha256,
                prehashed: false,
            }
    }));
    assert!(matches!(
        registry.crypto(
            verify_target,
            job(
                SignatureProfile::HashMlDsa {
                    parameter_set: MlDsaParameterSet::MlDsa44,
                    hash: PrehashAlgorithm::Sha256,
                    prehashed: false,
                },
                &message,
                &signature,
                b"desktop-ml-context"
            )
        ),
        Ok(BackendResult::Verified { .. })
    ));
}

#[test]
#[ignore = "requires tools/test-pqc-kryoptic.sh disposable store"]
fn montgomery_desktop_generation_and_agreement() {
    assert_eq!(
        std::env::var("PKCS11_TEST_PQC_ISOLATED").as_deref(),
        Ok("1")
    );
    let root =
        PathBuf::from(std::env::var_os("PKCS11_TEST_PQC_DIR").unwrap()).join("desktop-montgomery");
    std::fs::create_dir(&root).unwrap();
    let mut registry = Registry::default();
    let module = registry
        .load(&PathBuf::from(
            std::env::var_os("PKCS11_TEST_PQC_MODULE").unwrap(),
        ))
        .unwrap();
    let token = registry.modules[0]
        .entry
        .tokens
        .iter()
        .find(|token| token.label == "pqc-test")
        .unwrap()
        .id;
    assert!(
        registry
            .capabilities(module, token)
            .unwrap()
            .contains(&GenerationKind::Montgomery(
                pkcs11_client::MontgomeryCurve::X25519
            ))
    );
    registry
        .login(
            module,
            token,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();
    managed(
        registry.manage(
            module,
            token,
            ManagementAction::Generate {
                kind: GenerationKind::Montgomery(pkcs11_client::MontgomeryCurve::X25519),
                id: b"desktop-mont-a".to_vec(),
                label: b"desktop-mont-a".to_vec(),
                always_authenticate: false,
            },
        ),
        None,
    );
    let mut objects = managed(
        registry.manage(
            module,
            token,
            ManagementAction::Generate {
                kind: GenerationKind::Montgomery(pkcs11_client::MontgomeryCurve::X25519),
                id: b"desktop-mont-b".to_vec(),
                label: b"desktop-mont-b".to_vec(),
                always_authenticate: false,
            },
        ),
        None,
    );
    let (_, uri) = registry.location(module, token).unwrap();
    let public_a = objects
        .iter()
        .find(|entry| {
            entry.label == "desktop-mont-a" && entry.class == Some(ObjectClass::PUBLIC_KEY)
        })
        .unwrap()
        .id;
    let public_b = objects
        .iter()
        .find(|entry| {
            entry.label == "desktop-mont-b" && entry.class == Some(ObjectClass::PUBLIC_KEY)
        })
        .unwrap()
        .id;
    let mut peer_a = None;
    let mut peer_b = None;
    for (id, destination) in [(public_a, &mut peer_a), (public_b, &mut peer_b)] {
        let (reference, _) = registry.reference(module, token, id).unwrap();
        let key = PublicKeyRef::new(reference.uri().to_string().parse().unwrap()).unwrap();
        let mut session = registry.modules[0]
            .provider
            .management(&uri, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        let der = session.export_montgomery_public_key(&key).unwrap();
        session.close().unwrap();
        let path = root.join(format!("peer-{}.der", destination as *mut _ as usize));
        std::fs::write(&path, der).unwrap();
        *destination = Some(path);
    }
    for (label, peer, id) in [
        (
            "desktop-mont-a",
            peer_b.unwrap(),
            b"desktop-derived-a".to_vec(),
        ),
        (
            "desktop-mont-b",
            peer_a.unwrap(),
            b"desktop-derived-b".to_vec(),
        ),
    ] {
        let target = key_scope(module, token, &objects, label);
        let profile = match registry.crypto_options(target, false).unwrap() {
            BackendResult::KeyOptions {
                profile: KeyProfile::Montgomery(curve),
                ..
            } => KeyProfile::Montgomery(curve),
            _ => panic!("expected Montgomery profile"),
        };
        objects = managed(
            registry.key_operation(
                target,
                profile,
                KeyJob::DeriveMontgomery {
                    peer,
                    kdf: MontgomeryKdfChoice::X963Sha256,
                    shared_info: b"desktop agreement".to_vec(),
                    output: MontgomeryOutputChoice::Aes128,
                    length: None,
                    id: id.clone(),
                    label: id,
                },
            ),
            None,
        );
    }
    let secret = |label: &str| {
        let (reference, _) = registry
            .reference(
                module,
                token,
                objects
                    .iter()
                    .find(|entry| {
                        entry.label == label && entry.class == Some(ObjectClass::SECRET_KEY)
                    })
                    .unwrap()
                    .id,
            )
            .unwrap();
        ObjectRef::new(reference.uri().to_string().parse().unwrap()).unwrap()
    };
    let a = secret("desktop-derived-a");
    let b = secret("desktop-derived-b");
    let nonce = [0x24; 12];
    let plaintext = b"desktop Montgomery agreement";
    let mut session = registry.modules[0]
        .provider
        .management(&uri, SessionMode::ReadOnly, Authentication::None)
        .unwrap();
    let ciphertext = session
        .encrypt_aes_gcm(
            &a,
            &AesGcmEncryptRequest {
                nonce: &nonce,
                aad: b"desktop",
                plaintext,
            },
        )
        .unwrap();
    let decrypted = session
        .decrypt_aes_gcm(
            &b,
            &AesGcmDecryptRequest {
                nonce: &nonce,
                aad: b"desktop",
                ciphertext: &ciphertext,
            },
        )
        .unwrap();
    assert_eq!(decrypted.expose_secret(), plaintext);
    session.close().unwrap();
}
