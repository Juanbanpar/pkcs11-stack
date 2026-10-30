// SPDX-License-Identifier: MIT OR Apache-2.0
//! Single-part encryption uses the exact bound without a native size query/retry.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod fixture;
use pkcs11_runtime::{AesGcmEncryptRequest, Error, Module, ObjectRef, SessionMode};
#[test]
fn exact_capacity_native_errors_malformed_lengths_and_nonce_changes() {
    for headers in ["2.40", "3.0", "3.1", "3.2"] {
        for message in [b"".as_slice(), b"abc"] {
            for fault in 0..=8 {
                let fixture =
                    fixture::MetadataModule::with_headers("aes_gcm_single.c", fault, headers);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                let key =
                    ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap())
                        .unwrap();
                let result = session.encrypt_aes_gcm(
                    &key,
                    &AesGcmEncryptRequest {
                        nonce: &[0xa5; 12],
                        aad: b"",
                        plaintext: message,
                    },
                );
                if fault == 0 {
                    let expected: Vec<u8> =
                        message.iter().map(|b| b ^ 0x80).chain([0xef; 16]).collect();
                    assert_eq!(result.unwrap(), expected);
                    assert_eq!(
                        session.info().unwrap().device_error(),
                        (1 << 24) | (1 << 16)
                    );
                } else {
                    assert!(result.is_err(), "{headers}/{fault}");
                    if fault <= 6 {
                        assert!(matches!(session.info(), Err(Error::Closed)));
                    } else {
                        session.info().unwrap();
                    }
                }
                session.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
