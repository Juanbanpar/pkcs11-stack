// SPDX-License-Identifier: MIT OR Apache-2.0
//! Validation flags belong to the operation's session and retain opaque bits.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_runtime::{Error, Module, ObjectRef, SessionMode};

#[test]
fn flags_distinguish_zero_unavailable_unknown_bits_and_provider_failure() {
    // Native unsigned long can be 32 or 64 bits.
    #[allow(clippy::useless_conversion)]
    let maximum: u64 = std::os::raw::c_ulong::MAX.into();
    for fault in 0..=9 {
        let fixture = MetadataModule::from_source("session_validation.c", fault);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        if matches!(fault, 3 | 7) {
            assert!(session.session_validation_flags().is_err());
            assert!(matches!(session.info(), Err(Error::Closed)));
        } else {
            let unavailable = matches!(fault, 1 | 2 | 6 | 8 | 9);
            assert_eq!(
                session.session_validation_flags().unwrap(),
                if unavailable { None } else { Some(0) }
            );
            let key = ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap())
                .unwrap();
            session.mac_aes_cmac(&key, b"message").unwrap();
            let expected = if unavailable {
                None
            } else if fault == 4 {
                Some(0)
            } else if fault == 5 {
                Some(maximum)
            } else {
                Some(0x80000001)
            };
            assert_eq!(session.session_validation_flags().unwrap(), expected);
            if !unavailable {
                let fresh = token.open_session(SessionMode::ReadOnly).unwrap();
                assert_eq!(fresh.session_validation_flags().unwrap(), Some(0));
                fresh.close().unwrap();
                assert_eq!(session.session_validation_flags().unwrap(), expected);
            }
            session.info().unwrap();
        }
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}

#[test]
fn legacy_metadata_table_does_not_expose_validation_flags() {
    let fixture = MetadataModule::new(0);
    let module = Module::load(fixture.path()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
        .unwrap();
    let session = token.open_session(SessionMode::ReadOnly).unwrap();
    assert_eq!(session.session_validation_flags().unwrap(), None);
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
