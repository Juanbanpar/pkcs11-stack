// SPDX-License-Identifier: MIT OR Apache-2.0
//! Official headers, bounded output, authentication boundary and exclusive sessions.
#![cfg(unix)]
#[path = "fixtures/aes_gcm_stream_module.rs"]
mod fixture;
use fixture::AesGcmStreamModule;
use pkcs11_runtime::*;
use secrecy::ExposeSecret;
fn key() -> ObjectRef {
    ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap()
}
fn parameters() -> AesGcmStreamParameters<'static> {
    AesGcmStreamParameters {
        nonce: &[0xA5; 12],
        aad: &[],
        maximum_plaintext: 3,
    }
}
fn ciphertext(message: &[u8]) -> Vec<u8> {
    message.iter().map(|b| b ^ 0x80).chain([0xEF; 16]).collect()
}
fn with_fixture(
    fixture: AesGcmStreamModule,
    test: impl FnOnce(&Module, &mut Session<'_>, &Session<'_>),
) {
    let module = Module::load(fixture.path()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
        .unwrap();
    let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
    test(&module, &mut session, &watcher);
    session.close().unwrap();
    watcher.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
#[test]
fn all_tables_key_sizes_and_chunk_boundaries_match_the_fixed_profile() {
    for (major, minor) in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        for length in [16, 24, 32] {
            for aad_length in [0, 3] {
                with_fixture(
                    AesGcmStreamModule::new(major, minor, 0, length, aad_length),
                    |module, session, _| {
                        assert!(!module.supports_function(Function::Encrypt));
                        assert!(!module.supports_function(Function::Decrypt));
                        let aad = vec![0xA6; aad_length];
                        let parameters = AesGcmStreamParameters {
                            aad: &aad,
                            ..parameters()
                        };
                        for operation in [AesGcmOperation::Encrypt, AesGcmOperation::Decrypt] {
                            assert_eq!(
                                session
                                    .aes_gcm_streaming_capabilities(&key(), operation)
                                    .unwrap()
                                    .key_size
                                    .length(),
                                usize::from(length)
                            );
                        }
                        for message in [&[][..], b"abc"] {
                            let mut operation = session
                                .start_aes_gcm_encryption(&key(), parameters)
                                .unwrap();
                            assert_eq!(
                                operation.capabilities().key_size.length(),
                                usize::from(length)
                            );
                            let mut encrypted = operation.update(&[]).unwrap();
                            for chunk in message.chunks(1) {
                                encrypted.extend(operation.update(chunk).unwrap());
                            }
                            encrypted.extend(operation.finish().unwrap());
                            assert_eq!(encrypted, ciphertext(message));
                            let mut operation = session
                                .start_aes_gcm_decryption(&key(), parameters)
                                .unwrap();
                            assert_eq!(
                                operation.capabilities().key_size.length(),
                                usize::from(length)
                            );
                            operation.update(&[]).unwrap();
                            for chunk in encrypted.chunks(1) {
                                operation.update(chunk).unwrap();
                            }
                            assert_eq!(operation.finish().unwrap().expose_secret(), message);
                            session.info().unwrap();
                        }
                    },
                );
            }
        }
    }
    with_fixture(AesGcmStreamModule::new(3, 2, 30, 16, 0), |_, session, _| {
        let mut operation = session
            .start_aes_gcm_encryption(&key(), parameters())
            .unwrap();
        assert!(operation.update(b"a").unwrap().is_empty());
        assert!(operation.update(b"bc").unwrap().is_empty());
        assert_eq!(operation.finish().unwrap(), ciphertext(b"abc"));
    });
}
#[test]
fn policy_metadata_permissions_and_multipart_pointers_fail_before_init() {
    for fault in 0..=15 {
        with_fixture(
            AesGcmStreamModule::new(3, 2, fault, 16, 0),
            |_, session, watcher| {
                for parameters in [
                    AesGcmStreamParameters {
                        maximum_plaintext: AES_GCM_MAXIMUM_PLAINTEXT + 1,
                        ..parameters()
                    },
                    AesGcmStreamParameters {
                        aad: &[0; AES_GCM_MAXIMUM_AAD + 1],
                        ..parameters()
                    },
                ] {
                    assert!(
                        session
                            .start_aes_gcm_encryption(&key(), parameters)
                            .is_err()
                    );
                    assert!(
                        session
                            .start_aes_gcm_decryption(&key(), parameters)
                            .is_err()
                    );
                }
                if matches!(fault, 1 | 3 | 5..=12) {
                    assert!(
                        session
                            .start_aes_gcm_encryption(&key(), parameters())
                            .is_err()
                    );
                }
                if matches!(fault,2|4|5..=9|13..=15) {
                    assert!(
                        session
                            .start_aes_gcm_decryption(&key(), parameters())
                            .is_err()
                    );
                }
                assert_eq!(watcher.info().unwrap().device_error(), 0);
                session.info().unwrap();
            },
        );
    }
    // An unavailable direction must not remove the opposite direction's permission.
    for (fault, encrypt) in [(1, false), (3, false), (2, true), (4, true)] {
        with_fixture(
            AesGcmStreamModule::new(3, 2, fault, 16, 0),
            |_, session, _| {
                if encrypt {
                    let operation = session
                        .start_aes_gcm_encryption(&key(), parameters())
                        .unwrap();
                    operation.finish().unwrap();
                } else {
                    let mut operation = session
                        .start_aes_gcm_decryption(&key(), parameters())
                        .unwrap();
                    operation.update(&ciphertext(&[])).unwrap();
                    operation.finish().unwrap();
                }
            },
        );
    }
}
#[test]
fn failed_native_calls_and_malformed_output_discard() {
    for encrypt in [true, false] {
        for fault in [
            16, 17, 18, 19, 20, 21, 22, 23, 25, 26, 27, 32, 33, 34, 36, 38,
        ] {
            if encrypt && matches!(fault, 36 | 38) {
                continue;
            }
            with_fixture(
                AesGcmStreamModule::new(3, 2, fault, 16, 0),
                |_, session, watcher| {
                    if encrypt {
                        match session.start_aes_gcm_encryption(&key(), parameters()) {
                            Err(_) => assert!(matches!(fault, 16 | 25 | 32)),
                            Ok(mut operation) => {
                                if matches!(fault, 17..=19 | 26 | 33 | 38) {
                                    assert!(operation.update(b"abc").is_err());
                                    assert!(matches!(operation.update(b"x"), Err(Error::Closed)));
                                    assert!(matches!(operation.cancel(), Err(Error::Closed)));
                                } else {
                                    operation.update(b"abc").unwrap();
                                    assert!(operation.finish().is_err());
                                }
                            }
                        }
                    } else {
                        match session.start_aes_gcm_decryption(&key(), parameters()) {
                            Err(_) => assert!(matches!(fault, 16 | 25 | 32)),
                            Ok(mut operation) => {
                                if matches!(fault, 17..=19 | 26 | 33 | 38) {
                                    assert!(operation.update(&ciphertext(b"abc")).is_err());
                                    assert!(matches!(operation.update(&[]), Err(Error::Closed)));
                                    assert!(matches!(operation.cancel(), Err(Error::Closed)));
                                } else {
                                    operation.update(&ciphertext(b"abc")).unwrap();
                                    assert!(operation.finish().is_err());
                                }
                            }
                        }
                    }
                    assert!(session.info().is_err());
                    let calls = watcher.info().unwrap().device_error();
                    assert_eq!(calls >> 24, 1);
                    assert_eq!(calls & 0xFF, 0);
                    assert_eq!(
                        calls >> 8 & 0xFF,
                        u64::from(matches!(fault, 20..=23 | 27 | 34 | 36))
                    );
                },
            );
        }
    }
}
#[test]
fn budgets_short_tags_and_abandonment_poison_without_finalizing_or_retrying() {
    for case in 0..5 {
        with_fixture(
            AesGcmStreamModule::new(3, 2, 0, 16, 0),
            |_, session, watcher| {
                match case {
                    0 => drop(
                        session
                            .start_aes_gcm_encryption(&key(), parameters())
                            .unwrap(),
                    ),
                    1 => drop(
                        session
                            .start_aes_gcm_decryption(&key(), parameters())
                            .unwrap(),
                    ),
                    2 => {
                        let mut operation = session
                            .start_aes_gcm_encryption(&key(), parameters())
                            .unwrap();
                        operation.update(b"abc").unwrap();
                        assert!(operation.update(b"x").is_err());
                        assert!(matches!(operation.finish(), Err(Error::Closed)));
                    }
                    3 => {
                        let mut operation = session
                            .start_aes_gcm_decryption(&key(), parameters())
                            .unwrap();
                        operation.update(&ciphertext(b"abc")).unwrap();
                        assert!(operation.update(b"x").is_err());
                        assert!(matches!(operation.finish(), Err(Error::Closed)));
                    }
                    _ => {
                        let mut operation = session
                            .start_aes_gcm_decryption(&key(), parameters())
                            .unwrap();
                        operation.update(&[0; 15]).unwrap();
                        assert!(matches!(
                            operation.finish(),
                            Err(Error::InvalidParameters(_))
                        ));
                    }
                }
                assert!(session.info().is_err());
                assert_eq!(watcher.info().unwrap().device_error() & 0xFFFF, 0);
            },
        );
    }
}
#[test]
fn explicit_cancel_checks_direction_table_pointer_and_native_confirmation() {
    for (major, minor, fault) in [
        (2, 40, 0),
        (3, 0, 0),
        (3, 1, 0),
        (3, 2, 0),
        (3, 2, 28),
        (3, 2, 29),
        (3, 2, 35),
    ] {
        for encrypt in [true, false] {
            with_fixture(
                AesGcmStreamModule::new(major, minor, fault, 16, 0),
                |_, session, watcher| {
                    let result = if encrypt {
                        let mut op = session
                            .start_aes_gcm_encryption(&key(), parameters())
                            .unwrap();
                        op.update(b"a").unwrap();
                        op.cancel()
                    } else {
                        let mut op = session
                            .start_aes_gcm_decryption(&key(), parameters())
                            .unwrap();
                        op.update(&[0xEF]).unwrap();
                        op.cancel()
                    };
                    if major >= 3 && fault == 0 {
                        result.unwrap();
                        session.info().unwrap();
                        let op = session
                            .start_aes_gcm_encryption(&key(), parameters())
                            .unwrap();
                        op.finish().unwrap();
                    } else {
                        assert!(result.is_err());
                        assert!(session.info().is_err());
                    }
                    assert_eq!(
                        watcher.info().unwrap().device_error() & 0xFF,
                        u64::from(major >= 3 && fault != 29)
                    );
                },
            );
        }
    }
}

#[test]
fn native_update_plaintext_is_quarantined_until_successful_authentication() {
    with_fixture(AesGcmStreamModule::new(3, 2, 24, 16, 0), |_, session, _| {
        let mut operation = session
            .start_aes_gcm_decryption(&key(), parameters())
            .unwrap();
        for chunk in ciphertext(b"abc").chunks(1) {
            operation.update(chunk).unwrap();
        }
        assert_eq!(operation.finish().unwrap().expose_secret(), b"abc");
        session.info().unwrap();
    });
}
