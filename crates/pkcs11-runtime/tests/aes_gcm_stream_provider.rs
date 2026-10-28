// SPDX-License-Identifier: MIT OR Apache-2.0
//! Required multipart AES-GCM cancellation and same-session reuse on Kryoptic.
use pkcs11_runtime::*;
use secrecy::{ExposeSecret, SecretString};
use std::num::NonZeroUsize;
#[test]
#[ignore = "requires the disposable Kryoptic runner"]
fn aes_gcm_cancellation_restores_encryption_decryption_and_pool_reuse() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let pin = SecretString::from("12345678");
    let sizes = [
        AesKeySize::Bits128,
        AesKeySize::Bits192,
        AesKeySize::Bits256,
    ];
    let mut setup = token.open_session(SessionMode::ReadWrite).unwrap();
    setup
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, size) in sizes.into_iter().enumerate() {
        setup
            .generate_aes_key(&AesKeyRequest {
                size,
                purpose: AesKeyPurpose::Encryption,
                id: &[0xC7, index as u8],
                label: b"multipart-gcm-cancel",
            })
            .unwrap();
    }
    setup.close().unwrap();
    let pool = SessionPool::new(token, SessionMode::ReadOnly, NonZeroUsize::new(1).unwrap());
    let mut lease = pool
        .try_acquire(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    let generation = lease.generation();
    for (index, size) in sizes.into_iter().enumerate() {
        let key = ObjectRef::new(
            format!("pkcs11:token=kdf-test;id=%C7%{index:02X};type=secret-key")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let session = lease.session();
        let message = vec![0xA5; 65539];
        let cancel_nonce = [index as u8; 12];
        let mut operation = session
            .start_aes_gcm_encryption(
                &key,
                AesGcmStreamParameters {
                    nonce: &cancel_nonce,
                    aad: &[],
                    maximum_plaintext: message.len(),
                },
            )
            .unwrap();
        operation.update(b"cancel encryption").unwrap();
        operation.cancel().unwrap();
        session.info().unwrap();
        let nonce = [0xA0 + index as u8; 12];
        let parameters = AesGcmStreamParameters {
            nonce: &nonce,
            aad: b"cancel test context",
            maximum_plaintext: message.len(),
        };
        let mut operation = session.start_aes_gcm_encryption(&key, parameters).unwrap();
        assert_eq!(operation.capabilities().key_size, size);
        let mut encrypted = Vec::new();
        for chunk in message.chunks(3071) {
            encrypted.extend(operation.update(chunk).unwrap());
        }
        encrypted.extend(operation.finish().unwrap());
        let plaintext = session
            .decrypt_aes_gcm(
                &key,
                &AesGcmDecryptRequest {
                    nonce: &nonce,
                    aad: parameters.aad,
                    ciphertext: &encrypted,
                },
            )
            .unwrap();
        assert_eq!(plaintext.expose_secret(), &message);
        let mut operation = session.start_aes_gcm_decryption(&key, parameters).unwrap();
        operation.update(&encrypted[..3]).unwrap();
        operation.cancel().unwrap();
        session.info().unwrap();
        let mut operation = session.start_aes_gcm_decryption(&key, parameters).unwrap();
        for chunk in encrypted.chunks(3071) {
            operation.update(chunk).unwrap();
        }
        assert_eq!(operation.finish().unwrap().expose_secret(), &message);
        session.info().unwrap();
    }
    drop(lease);
    let lease = pool.try_acquire(Authentication::None).unwrap();
    assert_eq!(lease.generation(), generation);
    drop(lease);
    pool.close().unwrap();
    module.finalize().unwrap();
}
