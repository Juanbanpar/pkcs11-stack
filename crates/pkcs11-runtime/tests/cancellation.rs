// SPDX-License-Identifier: MIT OR Apache-2.0
//! Exact cancellation flags and lifecycle behavior across independent table layouts.
#![cfg(unix)]
#[path = "fixtures/cancellation_module.rs"]
mod fixture;
use cryptoki::{
    context::Function as NativeFunction,
    error::{Error as NativeError, RvError},
};
use fixture::CancellationModule;
use pkcs11_runtime::*;
use std::num::NonZeroUsize;

#[test]
fn selected_tables_flags_empty_noop_and_combined_cancellation() {
    for (major, minor) in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        let fixture = CancellationModule::new(major, minor, 0);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=digest".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        if major == 2 {
            assert!(matches!(
                session.cancel_operations(CancelFlags::DIGEST),
                Err(Error::CancellationUnavailable)
            ));
            assert!(matches!(session.info(), Err(Error::Closed)));
        } else {
            let mut count = 0;
            for (flag, value) in [
                (CancelFlags::FIND_OBJECTS, 0x40),
                (CancelFlags::ENCRYPT, 0x100),
                (CancelFlags::DECRYPT, 0x200),
                (CancelFlags::DIGEST, 0x400),
                (CancelFlags::SIGN, 0x800),
                (CancelFlags::VERIFY, 0x2000),
                (CancelFlags::empty(), 0),
                (
                    CancelFlags::DIGEST | CancelFlags::SIGN | CancelFlags::VERIFY,
                    0x2c00,
                ),
            ] {
                session.cancel_operations(flag).unwrap();
                count += 1;
                assert_eq!(
                    session.info().unwrap().device_error(),
                    count * 0x10000 + value
                );
            }
            let flags = CancelFlags::from_bits_retain(0x80000000);
            assert!(matches!(
                session.cancel_operations(flags),
                Err(Error::InvalidParameters(_))
            ));
            assert_eq!(
                session.info().unwrap().device_error(),
                count * 0x10000 + 0x2c00
            );
            let mut operation = session.start_digest(HashAlgorithm::Sha256).unwrap();
            operation.update(b"message-canary").unwrap();
            operation.cancel().unwrap();
            assert_eq!(
                session.info().unwrap().device_error(),
                (count + 1) * 0x10000 + 0x400
            );
            assert_eq!(
                session
                    .digest(HashAlgorithm::Sha256, b"new message")
                    .unwrap(),
                vec![0xAB; 32]
            );
        }
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
#[test]
fn failed_or_unavailable_cancellation_cannot_restore_a_session() {
    for fault in 1..=11 {
        let fixture = CancellationModule::new(3, 2, fault);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=digest".parse().unwrap())
            .unwrap();
        let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let mut operation = session.start_digest(HashAlgorithm::Sha256).unwrap();
        if fault == 9 {
            assert!(operation.update(b"read-canary").is_err());
            assert!(matches!(operation.cancel(), Err(Error::Closed)));
        } else if fault == 10 {
            assert!(operation.finish().is_err());
        } else {
            let error = operation.cancel().unwrap_err();
            let expected = match fault {
                1 => None,
                2 => Some(RvError::FunctionNotSupported),
                3 | 11 => Some(RvError::OperationCancelFailed),
                4 => Some(RvError::DeviceError),
                5 => Some(RvError::FunctionFailed),
                6 => Some(RvError::OperationActive),
                7 => Some(RvError::Pending),
                8 => Some(RvError::GeneralError),
                _ => unreachable!(),
            };
            match (error, expected) {
                (Error::CancellationUnavailable, None) => {}
                (
                    Error::Backend {
                        source: NativeError::Pkcs11(actual, NativeFunction::SessionCancel),
                        ..
                    },
                    Some(expected),
                ) => assert_eq!(actual, expected),
                (error, _) => panic!("unexpected cancellation error: {error}"),
            }
        }
        assert!(matches!(session.info(), Err(Error::Closed)));
        assert!(matches!(
            session.cancel_operations(CancelFlags::all()),
            Err(Error::Closed)
        ));
        let expected_count = u64::from(!matches!(fault, 1 | 9 | 10));
        assert_eq!(
            watcher.info().unwrap().device_error() / 0x10000,
            expected_count
        );
        if !matches!(fault, 9 | 10) {
            let mut other = token.open_session(SessionMode::ReadOnly).unwrap();
            assert!(
                other
                    .cancel_operations(
                        CancelFlags::DIGEST | CancelFlags::SIGN | CancelFlags::VERIFY
                    )
                    .is_err()
            );
            assert!(matches!(other.info(), Err(Error::Closed)));
            assert_eq!(
                watcher.info().unwrap().device_error(),
                (expected_count + u64::from(fault != 1)) * 0x10000
                    + if fault == 1 { 0 } else { 0x2c00 }
            );
            other.close().unwrap();
        }
        session.close().unwrap();
        watcher.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
#[test]
fn legacy_selection_and_drop_keep_close_discard_behavior() {
    for (major, minor, fault) in [(2, 40, 0), (3, 2, 0), (2, 40, 12)] {
        let fixture = CancellationModule::new(major, minor, fault);
        let module = Module::load_with_options(
            fixture.path(),
            ModuleOptions {
                interface: InterfaceSelection::Exact(InterfaceVersion::V2_40),
            },
        )
        .unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=digest".parse().unwrap())
            .unwrap();
        let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        session
            .start_digest(HashAlgorithm::Sha256)
            .unwrap()
            .cancel()
            .unwrap_err();
        assert!(matches!(session.info(), Err(Error::Closed)));
        assert_eq!(watcher.info().unwrap().device_error(), 0);
        session.close().unwrap();
        watcher.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
    let fixture = CancellationModule::new(3, 2, 0);
    let module = Module::load(fixture.path()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=digest".parse().unwrap())
        .unwrap();
    let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
    let pool = SessionPool::new(token, SessionMode::ReadOnly, NonZeroUsize::new(1).unwrap());
    {
        let mut lease = pool.try_acquire(Authentication::None).unwrap();
        drop(lease.session().start_digest(HashAlgorithm::Sha256).unwrap());
    }
    assert_eq!(watcher.info().unwrap().device_error(), 0);
    {
        let mut lease = pool.try_acquire(Authentication::None).unwrap();
        lease
            .session()
            .start_digest(HashAlgorithm::Sha256)
            .unwrap()
            .cancel()
            .unwrap();
        lease
            .session()
            .digest(HashAlgorithm::Sha256, b"abc")
            .unwrap();
    }
    assert_eq!(watcher.info().unwrap().device_error(), 0x10400);
    pool.close().unwrap();
    watcher.close().unwrap();
    module.finalize().unwrap();
}

#[test]
fn confirmed_cancellation_keeps_the_same_pooled_session() {
    // This fixture refuses a third open, so replacing rather than reusing the
    // cancelled lease cannot accidentally satisfy the test.
    let fixture = CancellationModule::new(3, 2, 13);
    let module = Module::load(fixture.path()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=digest".parse().unwrap())
        .unwrap();
    let watcher = token.open_session(SessionMode::ReadOnly).unwrap();
    let pool = SessionPool::new(token, SessionMode::ReadOnly, NonZeroUsize::new(1).unwrap());
    for _ in 0..3 {
        let mut lease = pool.try_acquire(Authentication::None).unwrap();
        lease
            .session()
            .start_digest(HashAlgorithm::Sha256)
            .unwrap()
            .cancel()
            .unwrap();
        lease
            .session()
            .digest(HashAlgorithm::Sha256, b"abc")
            .unwrap();
    }
    assert_eq!(watcher.info().unwrap().device_error(), 0x30400);
    pool.close().unwrap();
    watcher.close().unwrap();
    module.finalize().unwrap();
}
