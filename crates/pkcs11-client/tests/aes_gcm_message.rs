// SPDX-License-Identifier: MIT OR Apache-2.0
//! Exclusive client message lifecycle and real-provider/runtime agreement.
use pkcs11_client::*;
use secrecy::{ExposeSecret, SecretString};
#[cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod fixture;
#[cfg(unix)]
#[test]
fn native_message_results_failures_and_drop() {
    for fault in [0, 10, 12, 13, 14, 15, 16, 28] {
        let fixture = fixture::MetadataModule::from_source("aes_gcm_message.c", fault);
        let provider = Provider::load(fixture.path()).unwrap();
        let key =
            object_reference("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap();
        let mut session = provider
            .management(
                &"pkcs11:token=cmac".parse().unwrap(),
                SessionMode::ReadOnly,
                Authentication::None,
            )
            .unwrap();
        let mut ciphertext = vec![0xE1, 0xE2, 0xE3];
        ciphertext.extend([0xEF; 16]);
        let mut process = session.start_aes_gcm_message_decryption(&key).unwrap();
        let request = AesGcmDecryptRequest {
            nonce: &[0xa5; 12],
            aad: b"\0\xFF",
            ciphertext: &ciphertext,
        };
        let result = process.decrypt(&request);
        if matches!(fault, 10 | 12..=15) {
            assert!(result.is_err());
            assert!(process.finish().is_err());
        } else {
            assert_eq!(result.unwrap().expose_secret(), b"abc");
            if fault == 28 {
                assert!(process.decrypt(&request).is_err());
            }
            assert_eq!(process.finish().is_err(), matches!(fault, 16 | 28));
        }
        assert_eq!(session.state().is_ok(), fault == 0);
        if fault == 0 {
            {
                let _process = session.start_aes_gcm_message_encryption(&key).unwrap();
            }
            assert!(session.state().is_err());
        }
        session.close().unwrap();
        provider.finalize().unwrap();
    }
}
#[test]
#[ignore = "requires tools/test-nss.sh after runtime message fixtures"]
fn nss_client_messages_protected_keys_and_runtime_agreement() {
    assert_eq!(
        std::env::var("PKCS11_TEST_NSS_ISOLATED").as_deref(),
        Ok("1")
    );
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let pin = SecretString::from("12345678");
    let mut session = provider
        .management(
            &"pkcs11:token=kdf-test".parse().unwrap(),
            SessionMode::ReadOnly,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    for index in 0..3 {
        let label = format!("gcm-message-generated-{index}");
        let key = object_reference(
            format!("pkcs11:token=kdf-test;object={label};type=secret-key")
                .parse()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            session
                .aes_gcm_message_capabilities(&key, AesGcmOperation::Decrypt)
                .unwrap()
                .key_size
                .length(),
            16 + index * 8
        );
        let canonical = std::fs::read(
            std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap())
                .join(format!("{label}.ciphertext")),
        )
        .unwrap();
        let mut decrypt = session.start_aes_gcm_message_decryption(&key).unwrap();
        assert_eq!(
            decrypt
                .decrypt(&AesGcmDecryptRequest {
                    nonce: &[0x42; 12],
                    aad: b"binary\0\xff",
                    ciphertext: &canonical
                })
                .unwrap()
                .expose_secret(),
            b"generated message canary"
        );
        decrypt.finish().unwrap();
        let mut encrypt = session.start_aes_gcm_message_encryption(&key).unwrap();
        let mut messages = vec![];
        for i in 0..3 {
            let nonce = [0x50 + i; 12];
            let ciphertext = encrypt
                .encrypt(&AesGcmEncryptRequest {
                    nonce: &nonce,
                    aad: b"client context",
                    plaintext: b"client canary\0\xff",
                })
                .unwrap();
            messages.push((nonce, ciphertext));
        }
        encrypt.finish().unwrap();
        let mut decrypt = session.start_aes_gcm_message_decryption(&key).unwrap();
        for (nonce, ciphertext) in &messages {
            let plaintext = decrypt
                .decrypt(&AesGcmDecryptRequest {
                    nonce,
                    aad: b"client context",
                    ciphertext,
                })
                .unwrap();
            assert_eq!(plaintext.expose_secret(), b"client canary\0\xff");
            assert!(!format!("{plaintext:?}").contains("canary"));
        }
        decrypt.finish().unwrap();
        let mut tampered = canonical;
        tampered[0] ^= 1;
        let mut failure = provider
            .management(
                &"pkcs11:token=kdf-test".parse().unwrap(),
                SessionMode::ReadOnly,
                Authentication::None,
            )
            .unwrap();
        let mut decrypt = failure.start_aes_gcm_message_decryption(&key).unwrap();
        assert!(
            decrypt
                .decrypt(&AesGcmDecryptRequest {
                    nonce: &[0x42; 12],
                    aad: b"binary\0\xff",
                    ciphertext: &tampered
                })
                .is_err()
        );
        assert!(decrypt.finish().is_err());
        assert!(failure.state().is_err());
        failure.close().unwrap();
    }
    session.close().unwrap();
    provider.finalize().unwrap();
}
