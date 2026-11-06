// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pool validation precedes checkout; only native errors discard a session.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod fixture;
use pkcs11_client::*;
use std::num::NonZeroUsize;
#[test]
fn ccm_pool_preflight_reuse_and_native_failure_discard() {
    for fault in [0, 1, 17, 20, 21, 25] {
        let fixture = fixture::MetadataModule::with_case("aes_ccm.c", 3000 + fault, "3.2");
        let provider = Provider::load(fixture.path()).unwrap();
        let client = provider
            .client(
                &"pkcs11:token=cmac".parse().unwrap(),
                NonZeroUsize::new(1).unwrap(),
                SigningPolicy::default(),
            )
            .unwrap();
        let key =
            object_reference("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap();
        let lease = client.pool().try_acquire(Authentication::None).unwrap();
        let generation = lease.generation();
        let error = client
            .decrypt_aes_ccm(
                &key,
                &AesCcmDecryptRequest {
                    nonce: &[0xa5; 12],
                    aad: b"",
                    ciphertext: &[0; 15],
                },
                Authentication::None,
            )
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Input);
        drop(lease);
        let request = AesCcmEncryptRequest {
            nonce: &[0xa5; 12],
            aad: b"",
            plaintext: b"abc",
        };
        let result = client.encrypt_aes_ccm(&key, &request, Authentication::None);
        if fault == 0 {
            let ciphertext = result.unwrap();
            let plaintext = client
                .decrypt_aes_ccm(
                    &key,
                    &AesCcmDecryptRequest {
                        nonce: &[0xa5; 12],
                        aad: b"",
                        ciphertext: &ciphertext,
                    },
                    Authentication::None,
                )
                .unwrap();
            assert_eq!(secrecy::ExposeSecret::expose_secret(&plaintext), b"abc");
        } else {
            assert!(result.is_err());
        }
        assert_eq!(
            client
                .pool()
                .try_acquire(Authentication::None)
                .unwrap()
                .generation()
                != generation,
            fault >= 17
        );
        client.close().unwrap();
        provider.finalize().unwrap();
    }
}
