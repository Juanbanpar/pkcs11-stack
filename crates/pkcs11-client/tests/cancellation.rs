// SPDX-License-Identifier: MIT OR Apache-2.0
//! Client guard ownership and confirmed termination through independent OASIS tables.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/cancellation_module.rs"]
mod fixture;
use fixture::CancellationModule;
use pkcs11_client::*;

#[test]
fn client_digest_guard_can_cancel_and_reuse_only_after_native_confirmation() {
    for (major, minor, fault) in [
        (2, 40, 0),
        (3, 0, 0),
        (3, 1, 0),
        (3, 2, 0),
        (3, 2, 1),
        (3, 2, 2),
        (3, 2, 3),
        (3, 2, 9),
    ] {
        let fixture = CancellationModule::new(major, minor, fault);
        let provider = Provider::load(fixture.path()).unwrap();
        let mut session = provider
            .management(
                &"pkcs11:token=digest".parse().unwrap(),
                SessionMode::ReadOnly,
                Authentication::None,
            )
            .unwrap();
        let mut operation = session.start_digest(HashAlgorithm::Sha256).unwrap();
        if fault == 9 {
            assert!(operation.update(b"update-canary").is_err());
        } else {
            operation.update(b"message-canary").unwrap();
        }
        let result = operation.cancel();
        if major == 3 && fault == 0 {
            result.unwrap();
            session.state().unwrap();
            session.cancel_operations(CancelFlags::empty()).unwrap();
            assert_eq!(
                session
                    .digest_reader(
                        HashAlgorithm::Sha256,
                        &mut std::io::Cursor::new(b"new input")
                    )
                    .unwrap(),
                vec![0xAB; 32]
            );
            assert_eq!(
                session
                    .start_digest(HashAlgorithm::Sha256)
                    .unwrap()
                    .finish()
                    .unwrap(),
                vec![0xAB; 32]
            );
            drop(session.start_digest(HashAlgorithm::Sha256).unwrap());
            assert!(session.state().is_err());
            assert!(session.cancel_operations(CancelFlags::DIGEST).is_err());
        } else {
            assert!(result.is_err());
            assert!(session.state().is_err());
            assert!(session.cancel_operations(CancelFlags::DIGEST).is_err());
        }
        session.close().unwrap();
        provider.finalize().unwrap();
    }
}
