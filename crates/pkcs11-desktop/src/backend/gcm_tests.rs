// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use pkcs11_client::{AesGcmCapabilities, AesKeyPurpose, AesKeySize, ObjectClass};
#[path = "../../../pkcs11-runtime/tests/fixtures/aes_gcm_vectors.rs"]
mod vectors;
fn managed(result: BackendResult, error: Option<BackendError>) -> Vec<ObjectEntry> {
    match result {
        BackendResult::Managed {
            objects: Some(objects),
            error: actual,
            ..
        } => {
            assert_eq!(actual, error);
            objects
        }
        other => panic!("unexpected {other:?}"),
    }
}
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn scope(
    module: ResourceId,
    token: ResourceId,
    objects: &[ObjectEntry],
    label: &str,
    mode: CryptoMode,
) -> CryptoScope {
    CryptoScope {
        module,
        token,
        mode,
        object: objects
            .iter()
            .find(|object| object.label == label && object.class == Some(ObjectClass::SECRET_KEY))
            .unwrap()
            .id,
    }
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn software_token_gcm_files_known_answers_tampering_and_failure_cleanup() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root =
        PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap()).join("desktop-gcm");
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
    registry
        .login(
            module,
            token,
            LoginRole::User,
            SecretInput::Value("12345678".into()),
        )
        .unwrap();
    let mut objects = registry.objects(module, token).unwrap();
    // Decrypt a public NIST fixture written by the runtime runner, independently of GUI encryption.
    let (index, vector) = vectors::VECTORS
        .iter()
        .enumerate()
        .find(|(_, v)| v.key.len() == 32 && v.plaintext.len() == 26)
        .unwrap();
    let input = root.join("known-cipher");
    let aad = root.join("aad");
    let output = root.join("known-plain");
    std::fs::write(&input, hex(vector.ciphertext)).unwrap();
    std::fs::write(&aad, hex(vector.aad)).unwrap();
    let key = scope(
        module,
        token,
        &objects,
        &format!("gcm-vector-{index}"),
        CryptoMode::Decrypt,
    );
    let _ = managed(
        registry.cipher(
            key,
            CipherJob {
                choice: CipherParameters::AesGcm(AesGcmCapabilities {
                    key_size: AesKeySize::Bits128,
                }),
                aes_gcm: Some(AesGcmFiles {
                    nonce: hex(vector.nonce).try_into().unwrap(),
                    aad: Some(aad.clone()),
                }),
                input: input.clone(),
                output: output.clone(),
            },
        ),
        None,
    );
    assert_eq!(std::fs::read(&output).unwrap(), hex(vector.plaintext));
    let input = root.join("plain");
    std::fs::write(&input, b"GUI plaintext canary").unwrap();
    std::fs::write(&aad, b"context").unwrap();
    for (index, size) in [
        AesKeySize::Bits128,
        AesKeySize::Bits192,
        AesKeySize::Bits256,
    ]
    .into_iter()
    .enumerate()
    {
        let label = format!("desktop-file-gcm-{index}");
        managed(
            registry.manage(
                module,
                token,
                ManagementAction::Generate {
                    kind: GenerationKind::Aes(size, AesKeyPurpose::Encryption),
                    id: vec![0xBD, index as u8],
                    label: label.as_bytes().to_vec(),
                    always_authenticate: false,
                },
            ),
            None,
        );
        objects = registry.objects(module, token).unwrap();
        let encrypt = scope(module, token, &objects, &label, CryptoMode::Encrypt);
        let caps = CipherParameters::AesGcm(AesGcmCapabilities { key_size: size });
        assert!(
            matches!(registry.cipher_options(encrypt).unwrap(),BackendResult::CipherOptions { choices,.. } if choices==vec![caps])
        );
        let cipher = root.join(format!("cipher-{index}"));
        let output = root.join(format!("plain-{index}"));
        let job = |input: PathBuf, output: PathBuf, nonce, aad: Option<PathBuf>| CipherJob {
            choice: caps,
            aes_gcm: Some(AesGcmFiles { nonce, aad }),
            input,
            output,
        };
        objects = managed(
            registry.cipher(
                encrypt,
                job(input.clone(), cipher.clone(), [1; 12], Some(aad.clone())),
            ),
            None,
        );
        let bytes = std::fs::read(&cipher).unwrap();
        assert_eq!(bytes.len(), b"GUI plaintext canary".len() + 16);
        objects = managed(
            registry.cipher(
                scope(module, token, &objects, &label, CryptoMode::Decrypt),
                job(cipher.clone(), output.clone(), [1; 12], Some(aad.clone())),
            ),
            None,
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"GUI plaintext canary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Creating a new output is required before encryption; existing input/output is preserved.
        objects = managed(
            registry.cipher(
                scope(module, token, &objects, &label, CryptoMode::Encrypt),
                job(input.clone(), input.clone(), [2; 12], None),
            ),
            Some(BackendError::FileWrite),
        );
        assert_eq!(std::fs::read(&input).unwrap(), b"GUI plaintext canary");
        for mutation in 0..4 {
            let mut bytes = bytes.clone();
            let mut nonce = [1; 12];
            let mut aad_path = aad.clone();
            match mutation {
                0 => nonce[0] ^= 1,
                1 => {
                    aad_path = root.join("wrong-aad");
                    std::fs::write(&aad_path, b"wrong").unwrap();
                }
                2 => bytes[0] ^= 1,
                _ => *bytes.last_mut().unwrap() ^= 1,
            }
            let corrupted = root.join(format!("corrupt-{index}-{mutation}"));
            let rejected = root.join(format!("rejected-{index}-{mutation}"));
            std::fs::write(&corrupted, &bytes).unwrap();
            objects = managed(
                registry.cipher(
                    scope(module, token, &objects, &label, CryptoMode::Decrypt),
                    job(corrupted, rejected.clone(), nonce, Some(aad_path)),
                ),
                Some(BackendError::Client(pkcs11_client::ErrorKind::Runtime)),
            );
            assert!(std::fs::read(&rejected).unwrap().is_empty());
        }
        let big = root.join("big");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(pkcs11_client::AES_GCM_MAXIMUM_PLAINTEXT as u64 + 1)
            .unwrap();
        let rejected = root.join(format!("too-big-{index}"));
        let _ = managed(
            registry.cipher(
                scope(module, token, &objects, &label, CryptoMode::Encrypt),
                job(big, rejected.clone(), [3; 12], None),
            ),
            Some(BackendError::CipherInput),
        );
        assert!(!rejected.exists());
    }
    registry.close().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
