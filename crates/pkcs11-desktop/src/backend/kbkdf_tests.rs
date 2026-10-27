// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{BackendResult, LoginRole, ManagementAction, ObjectEntry, SecretInput};
use pkcs11_client::{
    AesGcmDecryptRequest, AesGcmEncryptRequest, DigestAlgorithm, KbkdfMode, KbkdfOutput,
};
use secrecy::ExposeSecret;
use std::path::PathBuf;
fn managed(result: BackendResult) -> Vec<ObjectEntry> {
    let BackendResult::Managed {
        error,
        objects: Some(objects),
        ..
    } = result
    else {
        panic!("managed result")
    };
    assert_eq!(error, None);
    objects
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh SP800-108 provider"]
fn persistent_kbkdf_desktop_rechecks_profiles_and_matches_runtime_outputs() {
    for mode in KbkdfMode::ALL {
        check_mode(mode);
    }
}
fn check_mode(mode: KbkdfMode) {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
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
    let mut objects = registry.objects(module, token).unwrap();
    for (index, digest) in [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ]
    .into_iter()
    .enumerate()
    {
        let scope = CryptoScope {
            module,
            token,
            object: objects
                .iter()
                .find(|o| o.identifier == format!("A0{index:02X}"))
                .unwrap()
                .id,
            mode: CryptoMode::Kbkdf,
        };
        let BackendResult::KeyOptions {
            profile: super::super::KeyProfile::Kbkdf(caps),
            ..
        } = registry.key_options(scope).unwrap()
        else {
            panic!("counter profile")
        };
        let job = || KbkdfJob {
            mode,
            iv: if mode == KbkdfMode::Feedback {
                vec![0xA5; digest.output_len()]
            } else {
                Vec::new()
            },
            digest,
            output: KbkdfOutput::Aes256,
            kdf_label: b"application".to_vec(),
            context: b"v1 context".to_vec(),
            id: vec![0xFA, 0x87, index as u8],
            label: format!("desktop-kbkdf-{index}").into_bytes(),
        };
        assert_eq!(
            registry.kbkdf_action(
                scope,
                {
                    let mut stale = caps;
                    stale.counter.as_mut().unwrap().input_length += 1;
                    stale
                },
                KeyJob::Kbkdf(job())
            ),
            Err(BackendError::KeyOperationUnavailable)
        );
        let mut invalid_iv = job();
        invalid_iv.iv = vec![0; 1];
        assert_eq!(
            registry.kbkdf_action(scope, caps, KeyJob::Kbkdf(invalid_iv)),
            Err(BackendError::KbkdfInput)
        );
        let mut invalid = job();
        invalid.context = vec![0; 4097];
        assert_eq!(
            registry.kbkdf_action(scope, caps, KeyJob::Kbkdf(invalid)),
            Err(BackendError::KbkdfInput)
        );
        objects = managed(registry.key_operation(
            scope,
            super::super::KeyProfile::Kbkdf(caps),
            KeyJob::Kbkdf(job()),
        ));
        assert!(matches!(
            registry.key_options(scope),
            Err(BackendError::UnknownObject)
        ));
        let result = objects
            .iter()
            .find(|o| o.label == format!("desktop-kbkdf-{index}"))
            .unwrap()
            .id;
        let reference = registry.reference(module, token, result).unwrap().0;
        let canonical = pkcs11_client::object_reference(
            format!(
                "pkcs11:token=kdf-test;id=%FA%{:02X}%{index:02X};type=secret-key",
                if mode == KbkdfMode::Counter {
                    0x82
                } else {
                    0x8A
                }
            )
            .parse()
            .unwrap(),
        )
        .unwrap();
        let (_, uri) = registry.location(module, token).unwrap();
        read_session(
            &registry.modules[0],
            &uri,
            SessionMode::ReadOnly,
            |session| {
                assert!(session.export_public(&reference).is_err());
                let nonce = [index as u8; 12];
                let ciphertext = session
                    .encrypt_aes_gcm(
                        &reference,
                        &AesGcmEncryptRequest {
                            nonce: &nonce,
                            aad: b"desktop counter proof",
                            plaintext: b"desktop counter agreement",
                        },
                    )
                    .unwrap();
                let recovered = session
                    .decrypt_aes_gcm(
                        &canonical,
                        &AesGcmDecryptRequest {
                            nonce: &nonce,
                            aad: b"desktop counter proof",
                            ciphertext: &ciphertext,
                        },
                    )
                    .unwrap();
                assert_eq!(recovered.expose_secret(), b"desktop counter agreement");
                Ok(())
            },
        )
        .unwrap();
        objects =
            managed(registry.manage(module, token, ManagementAction::Delete { object: result }));
    }
    registry.close().unwrap();
}
