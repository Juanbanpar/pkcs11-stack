// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pooled and management ChaCha20-Poly1305 operations agree with the RFC 8439 reference profiles.
#[path = "../../pkcs11-runtime/tests/fixtures/chacha20_poly1305_vectors.rs"]
mod vectors;
use pkcs11_client::*;
use secrecy::{ExposeSecret, SecretString};
use std::num::NonZeroUsize;
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh after runtime AES-ChaCha20-Poly1305 provisioning"]
fn chacha_client_vectors_both_apis_and_authentication_failure() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=kdf-test".parse().unwrap();
    assert!(
        provider
            .generation_capabilities(&token)
            .unwrap()
            .chacha20_poly1305
    );
    let pin = SecretString::from("12345678");
    let auth = || Authentication::User(Pin::Value(&pin));
    let client = provider
        .client(
            &token,
            NonZeroUsize::new(1).unwrap(),
            SigningPolicy::default(),
        )
        .unwrap();
    for (i, v) in vectors::VECTORS.iter().enumerate() {
        let key = object_reference(
            format!("pkcs11:token=kdf-test;object=chacha-kat-{i};type=secret-key")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let nonce = hex(v.nonce).try_into().unwrap();
        let aad = hex(v.aad);
        let message = hex(v.plaintext);
        let ciphertext = hex(v.ciphertext);
        let encryption = ChaCha20Poly1305EncryptRequest {
            nonce: &nonce,
            aad: &aad,
            plaintext: &message,
        };
        let decryption = ChaCha20Poly1305DecryptRequest {
            nonce: &nonce,
            aad: &aad,
            ciphertext: &ciphertext,
        };
        assert_eq!(
            client
                .chacha20_poly1305_capabilities(&key, ChaCha20Poly1305Operation::Encrypt, auth())
                .unwrap()
                .key_length,
            v.key.len() / 2
        );
        assert_eq!(
            client
                .encrypt_chacha20_poly1305(&key, &encryption, auth())
                .unwrap(),
            ciphertext
        );
        assert_eq!(
            client
                .decrypt_chacha20_poly1305(&key, &decryption, auth())
                .unwrap()
                .expose_secret(),
            &message
        );
        let before = client.pool().try_acquire(auth()).unwrap().generation();
        let mut bad = ciphertext.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(
            client
                .decrypt_chacha20_poly1305(
                    &key,
                    &ChaCha20Poly1305DecryptRequest {
                        ciphertext: &bad,
                        ..decryption
                    },
                    auth()
                )
                .is_err()
        );
        assert_ne!(
            client.pool().try_acquire(auth()).unwrap().generation(),
            before
        );
        assert_eq!(
            client
                .decrypt_chacha20_poly1305(&key, &decryption, auth())
                .unwrap()
                .expose_secret(),
            &message
        );
        // The live pool already owns the token-wide USER login.
        let mut management = provider
            .management(&token, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        assert_eq!(
            management
                .encrypt_chacha20_poly1305(&key, &encryption)
                .unwrap(),
            ciphertext
        );
        assert_eq!(
            management
                .decrypt_chacha20_poly1305(&key, &decryption)
                .unwrap()
                .expose_secret(),
            &message
        );
        management.close().unwrap();
    }
    client.close().unwrap();
    provider.finalize().unwrap();
}
