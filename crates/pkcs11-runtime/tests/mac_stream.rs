// SPDX-License-Identifier: MIT OR Apache-2.0
//! Multipart MAC ABI, output bounds, permissions and session lifecycle.
#![cfg(unix)]
#[path = "fixtures/mac_stream_module.rs"]
mod fixture;
use fixture::MacStreamModule;
use pkcs11_runtime::*;

fn key() -> ObjectRef {
    ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap()
}
fn generate<'a>(
    session: &'a mut Session<'_>,
    hmac: bool,
    general: bool,
) -> Result<MacGeneration<'a>, Error> {
    if hmac {
        session.start_hmac(
            &key(),
            HmacAlgorithm::Sha256,
            if general {
                HmacTagProfile::General { tag_length: 16 }
            } else {
                HmacTagProfile::Full
            },
        )
    } else {
        session.start_aes_cmac(
            &key(),
            if general {
                AesCmacProfile::General { tag_length: 8 }
            } else {
                AesCmacProfile::Full
            },
        )
    }
}
fn verify<'a>(
    session: &'a mut Session<'_>,
    hmac: bool,
    general: bool,
) -> Result<MacVerification<'a>, Error> {
    if hmac {
        session.start_hmac_verification(
            &key(),
            HmacAlgorithm::Sha256,
            if general {
                HmacTagProfile::General { tag_length: 16 }
            } else {
                HmacTagProfile::Full
            },
        )
    } else {
        session.start_aes_cmac_verification(
            &key(),
            if general {
                AesCmacProfile::General { tag_length: 8 }
            } else {
                AesCmacProfile::Full
            },
        )
    }
}
#[test]
fn exact_parameters_bounded_output_and_completed_mismatches_across_versions() {
    for (major, minor) in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        for (hmac, general) in [(false, false), (false, true), (true, false), (true, true)] {
            let fixture = MacStreamModule::new(major, minor, 0, hmac, general);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let length = if hmac {
                if general { 16 } else { 32 }
            } else if general {
                8
            } else {
                16
            };
            // Single-part C_Sign/C_Verify pointers are deliberately absent.
            for chunks in [vec![], vec![&[][..], b"a", b"stream-canary", &[][..]]] {
                let mut operation = generate(&mut session, hmac, general).unwrap();
                assert!(!format!("{operation:?}").contains("canary"));
                for chunk in &chunks {
                    operation.update(chunk).unwrap();
                }
                let tag = operation.finish().unwrap();
                assert_eq!(tag, vec![0xAB; length]);
                session.info().unwrap();
                for supplied in [
                    tag.clone(),
                    vec![],
                    vec![0xAB; length - 1],
                    vec![0xAC; length],
                ] {
                    let mut operation = verify(&mut session, hmac, general).unwrap();
                    for chunk in &chunks {
                        operation.update(chunk).unwrap();
                    }
                    let result = operation.finish(&supplied);
                    if supplied == tag {
                        result.unwrap();
                    } else {
                        assert!(matches!(result, Err(Error::MacMismatch)));
                    }
                    session.info().unwrap();
                }
            }
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn missing_functions_and_direction_permissions_fail_before_init() {
    for hmac in [false, true] {
        for fault in [1, 11, 12, 13, 14, 15, 29, 30, 31, 32] {
            let fixture = MacStreamModule::new(2, 40, fault, hmac, false);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let generation = matches!(fault, 1 | 12 | 14 | 29 | 30);
            if generation {
                assert!(matches!(
                    generate(&mut session, hmac, false),
                    Err(Error::UnsupportedMac)
                ));
            } else {
                assert!(matches!(
                    verify(&mut session, hmac, false),
                    Err(Error::UnsupportedMac)
                ));
            }
            assert_eq!(session.info().unwrap().device_error(), 0);
            // The opposite direction remains available even without the other pointers/permission.
            if generation {
                verify(&mut session, hmac, false)
                    .unwrap()
                    .finish(&vec![0xAB; if hmac { 32 } else { 16 }])
                    .unwrap();
            } else {
                generate(&mut session, hmac, false)
                    .unwrap()
                    .finish()
                    .unwrap();
            }
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn abandoned_or_failed_operations_never_restore_reuse_or_retry() {
    for hmac in [false, true] {
        for generation in [false, true] {
            for fault in [0, 19, 20, 21, 22, 23, 24, 25, 26] {
                if !generation && matches!(fault, 24..=26) {
                    continue;
                }
                let fixture = MacStreamModule::new(3, 2, fault, hmac, false);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                if generation {
                    match generate(&mut session, hmac, false) {
                        Err(_) => assert_eq!(fault, 20),
                        Ok(mut op) => match fault {
                            0 | 19 => {
                                if fault == 0 {
                                    op.update(b"abandoned").unwrap();
                                }
                                drop(op);
                            }
                            21 | 22 => {
                                assert!(op.update(b"failure").is_err());
                                assert!(matches!(op.update(b"retry"), Err(Error::Closed)));
                                assert!(matches!(op.cancel(), Err(Error::Closed)));
                            }
                            _ => assert!(op.finish().is_err()),
                        },
                    }
                } else {
                    match verify(&mut session, hmac, false) {
                        Err(_) => assert_eq!(fault, 20),
                        Ok(mut op) => match fault {
                            0 | 19 => {
                                if fault == 0 {
                                    op.update(b"abandoned").unwrap();
                                }
                                drop(op);
                            }
                            21 | 22 => {
                                assert!(op.update(b"failure").is_err());
                                assert!(matches!(op.update(b"retry"), Err(Error::Closed)));
                                assert!(matches!(op.finish(&[0xAB; 16]), Err(Error::Closed)));
                            }
                            _ => assert!(op.finish(&[0xAB; 16]).is_err()),
                        },
                    }
                }
                assert!(matches!(session.info(), Err(Error::Closed)));
                let calls = watcher.info().unwrap().device_error();
                assert_eq!(calls / 1000000, 1);
                assert_eq!(calls % 100, 0, "no implicit cancellation");
                assert_eq!(calls / 100 % 100, u64::from(matches!(fault, 23..=26)));
                assert_eq!(calls / 10000 % 100, u64::from(matches!(fault, 0 | 21 | 22)));
                session.close().unwrap();
                watcher.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
#[test]
fn explicit_cancellation_restores_only_confirmed_active_mac_operations() {
    for generation in [false, true] {
        for (major, minor, fault) in [
            (2, 40, 0),
            (3, 0, 0),
            (3, 1, 0),
            (3, 2, 0),
            (3, 2, 33),
            (3, 2, 34),
        ] {
            let fixture = MacStreamModule::new(major, minor, fault, false, false);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let result = if generation {
                let mut op = generate(&mut session, false, false).unwrap();
                op.update(b"cancel").unwrap();
                op.cancel()
            } else {
                let mut op = verify(&mut session, false, false).unwrap();
                op.update(b"cancel").unwrap();
                op.cancel()
            };
            if major >= 3 && fault == 0 {
                result.unwrap();
                session.info().unwrap();
                generate(&mut session, false, false)
                    .unwrap()
                    .finish()
                    .unwrap();
            } else {
                assert!(result.is_err());
                assert!(matches!(session.info(), Err(Error::Closed)));
            }
            assert_eq!(
                watcher.info().unwrap().device_error() % 100,
                u64::from(major >= 3 && fault != 34)
            );
            session.close().unwrap();
            watcher.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}

#[test]
fn completed_native_mismatches_and_provider_accepted_wrong_lengths_still_enforce_profile() {
    for hmac in [false, true] {
        for fault in [27, 28, 36] {
            let fixture = MacStreamModule::new(2, 40, fault, hmac, false);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            assert!(matches!(
                verify(&mut session, hmac, false).unwrap().finish(&[]),
                Err(Error::MacMismatch)
            ));
            session.info().unwrap();
            generate(&mut session, hmac, false)
                .unwrap()
                .finish()
                .unwrap();
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
