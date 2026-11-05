// SPDX-License-Identifier: MIT OR Apache-2.0
//! Official table layouts, message bounds, failures and exclusive lifecycle.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod fixture;
use pkcs11_runtime::{
    AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_PLAINTEXT, AesGcmDecryptRequest, AesGcmEncryptRequest,
    AesGcmOperation, Error, Module, ObjectRef, SessionMode,
};
use secrecy::ExposeSecret;
fn key() -> ObjectRef {
    ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap()
}
#[test]
fn official_tables_flags_permissions_exact_bounds_and_failed_sessions() {
    for headers in ["2.40", "3.0", "3.1", "3.2"] {
        for fault in 0..=28 {
            let fixture =
                fixture::MetadataModule::with_headers("aes_gcm_message.c", fault, headers);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            for direction in [AesGcmOperation::Encrypt, AesGcmOperation::Decrypt] {
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                let gate = headers == "2.40"
                    || matches!(fault, 19 | 22..=25 | 27)
                    || match direction {
                        AesGcmOperation::Encrypt => matches!(fault, 1 | 3..=5 | 20),
                        AesGcmOperation::Decrypt => matches!(fault, 2 | 6..=8 | 21),
                    };
                let caps = session.aes_gcm_message_capabilities(&key(), direction);
                if gate {
                    assert!(caps.is_err(), "{headers}/{fault}/{direction:?}: {caps:?}");
                    assert!(
                        match direction {
                            AesGcmOperation::Encrypt =>
                                session.start_aes_gcm_message_encryption(&key()).map(|_| ()),
                            AesGcmOperation::Decrypt =>
                                session.start_aes_gcm_message_decryption(&key()).map(|_| ()),
                        }
                        .is_err()
                    );
                    assert_eq!(session.info().unwrap().device_error(), 0);
                    session.close().unwrap();
                    continue;
                }
                assert_eq!(caps.unwrap().key_size.length(), 16);
                let completion_failure = matches!(fault, 10..=14 | 17 | 18 | 28)
                    || (fault == 15 && direction == AesGcmOperation::Decrypt);
                let mut nonce = [0xA5; 12];
                let mut ciphertext = vec![0xE1, 0xE2, 0xE3];
                ciphertext.extend([0xEF; 16]);
                let result = match direction {
                    AesGcmOperation::Encrypt => {
                        match session.start_aes_gcm_message_encryption(&key()) {
                            Err(e) => Err(e),
                            Ok(mut process) => {
                                assert_eq!(process.capabilities().key_size.length(), 16);
                                let mut result = Ok(());
                                for index in 0..3 {
                                    nonce[0] = index;
                                    let request = AesGcmEncryptRequest {
                                        nonce: &nonce,
                                        aad: b"\0\xFF",
                                        plaintext: if index == 2 { b"" } else { b"abc" },
                                    };
                                    let output = process.encrypt(&request);
                                    if completion_failure && (fault != 28 || index == 1) {
                                        assert!(output.is_err(), "{headers}/{fault}");
                                        assert!(matches!(
                                            process.encrypt(&request),
                                            Err(Error::Closed)
                                        ));
                                        result = output.map(|_| ());
                                        break;
                                    }
                                    assert_eq!(
                                        output.unwrap(),
                                        if index == 2 {
                                            vec![0xEF; 16]
                                        } else {
                                            ciphertext.clone()
                                        }
                                    );
                                }
                                if result.is_ok() {
                                    process.finish()
                                } else {
                                    assert!(matches!(process.finish(), Err(Error::Closed)));
                                    result
                                }
                            }
                        }
                    }
                    AesGcmOperation::Decrypt => {
                        match session.start_aes_gcm_message_decryption(&key()) {
                            Err(e) => Err(e),
                            Ok(mut process) => {
                                let mut result = Ok(());
                                for index in 0..3 {
                                    nonce[0] = index;
                                    let request = AesGcmDecryptRequest {
                                        nonce: &nonce,
                                        aad: b"\0\xFF",
                                        ciphertext: if index == 2 {
                                            &[0xEF; 16]
                                        } else {
                                            &ciphertext
                                        },
                                    };
                                    let output = process.decrypt(&request);
                                    if completion_failure && (fault != 28 || index == 1) {
                                        assert!(output.is_err(), "{headers}/{fault}");
                                        assert!(matches!(
                                            process.decrypt(&request),
                                            Err(Error::Closed)
                                        ));
                                        result = output.map(|_| ());
                                        break;
                                    }
                                    assert_eq!(
                                        output.unwrap().expose_secret(),
                                        if index == 2 { b"".as_slice() } else { b"abc" }
                                    );
                                }
                                if result.is_ok() {
                                    process.finish()
                                } else {
                                    assert!(matches!(process.finish(), Err(Error::Closed)));
                                    result
                                }
                            }
                        }
                    }
                };
                if fault == 9 || completion_failure || fault == 16 {
                    assert!(result.is_err(), "{headers}/{fault}/{direction:?}");
                    assert!(matches!(session.info(), Err(Error::Closed)));
                } else {
                    result.unwrap();
                    assert_eq!(
                        session.info().unwrap().device_error(),
                        (1 << 24) | (3 << 16) | (1 << 8)
                    );
                }
                session.close().unwrap();
            }
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn local_validation_keeps_process_active_and_drop_discards_session() {
    for headers in ["3.0", "3.1", "3.2"] {
        let fixture = fixture::MetadataModule::with_headers("aes_gcm_message.c", 0, headers);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        for direction in [AesGcmOperation::Encrypt, AesGcmOperation::Decrypt] {
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            match direction {
                AesGcmOperation::Encrypt => {
                    let mut p = session.start_aes_gcm_message_encryption(&key()).unwrap();
                    let request = AesGcmEncryptRequest {
                        nonce: &[0xA5; 12],
                        aad: &[],
                        plaintext: &[],
                    };
                    assert!(matches!(
                        p.encrypt(&AesGcmEncryptRequest {
                            plaintext: &vec![0; AES_GCM_MAXIMUM_PLAINTEXT + 1],
                            ..request
                        }),
                        Err(Error::InvalidParameters(_))
                    ));
                    assert!(matches!(
                        p.encrypt(&AesGcmEncryptRequest {
                            aad: &vec![0; AES_GCM_MAXIMUM_AAD + 1],
                            ..request
                        }),
                        Err(Error::InvalidParameters(_))
                    ));
                    p.encrypt(&AesGcmEncryptRequest {
                        aad: b"\0\xFF",
                        ..request
                    })
                    .unwrap();
                    p.finish().unwrap();
                    session.info().unwrap();
                    {
                        let _process = session.start_aes_gcm_message_encryption(&key()).unwrap();
                    }
                }
                AesGcmOperation::Decrypt => {
                    let mut p = session.start_aes_gcm_message_decryption(&key()).unwrap();
                    assert!(matches!(
                        p.decrypt(&AesGcmDecryptRequest {
                            nonce: &[0; 12],
                            aad: &[],
                            ciphertext: &[0; 15]
                        }),
                        Err(Error::InvalidParameters(_))
                    ));
                    p.finish().unwrap();
                    session.info().unwrap();
                    {
                        let _process = session.start_aes_gcm_message_decryption(&key()).unwrap();
                    }
                }
            }
            assert!(matches!(session.info(), Err(Error::Closed)));
            session.close().unwrap();
        }
        drop(token);
        module.finalize().unwrap();
    }
}
