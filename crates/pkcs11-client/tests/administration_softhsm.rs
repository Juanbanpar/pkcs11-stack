// SPDX-License-Identifier: MIT OR Apache-2.0
//! Administration acceptance in the runner's disposable token store.
use pkcs11_client::{Authentication, Error, ErrorKind, Pin, Provider, SessionMode};
use secrecy::SecretString;
#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn checked_token_initialization_and_pin_lifecycle() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let mut provider = Provider::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let snapshot = provider
        .tokens()
        .unwrap()
        .into_iter()
        .find(|token| token.info.label() == "admin-client-test")
        .unwrap();
    let target = snapshot.initialization_target();
    let uri = snapshot.uri().unwrap();
    let so = SecretString::from("87654321");
    let user = SecretString::from("12345678");
    let anchor = provider
        .management_owned(
            &uri,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&user)),
        )
        .unwrap();
    assert!(matches!(
        provider.initialize_token_checked(&target, &so, "must-not-erase"),
        Err(Error::ProviderInUse)
    ));
    anchor.close().unwrap();
    for stale in [
        {
            let mut changed = target.clone();
            changed.serial.push('x');
            changed
        },
        {
            let mut changed = target.clone();
            changed.initialized = false;
            changed
        },
        {
            let mut changed = target.clone();
            changed.slot_id = u64::MAX;
            changed
        },
    ] {
        assert_eq!(
            provider
                .initialize_token_checked(&stale, &so, "must-not-erase")
                .unwrap_err()
                .kind(),
            ErrorKind::Runtime
        );
    }
    let mut session = provider
        .management(
            &uri,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&user)),
        )
        .unwrap();
    session
        .import_data(b"erase-me", b"test", b"erase-me")
        .unwrap();
    session.close().unwrap();
    provider
        .initialize_token_checked(&target, &so, "admin-client-reset")
        .unwrap();
    assert!(
        provider
            .initialize_token_checked(&target, &so, "stale-selection")
            .is_err()
    );
    let snapshot = provider
        .tokens()
        .unwrap()
        .into_iter()
        .find(|token| token.info.label() == "admin-client-reset")
        .unwrap();
    assert!(!snapshot.info.user_pin_initialized());
    let uri = snapshot.uri().unwrap();
    let mut session = provider
        .management(
            &uri,
            SessionMode::ReadWrite,
            Authentication::SecurityOfficer(Pin::Value(&so)),
        )
        .unwrap();
    assert!(
        session
            .objects(&[pkcs11_client::AttributeType::Label])
            .unwrap()
            .is_empty()
    );
    session.initialize_pin(&user).unwrap();
    session.close().unwrap();
    let new_user = SecretString::from("23456789");
    let mut session = provider
        .management(
            &uri,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&user)),
        )
        .unwrap();
    session.change_pin(&user, &new_user).unwrap();
    session.close().unwrap();
    assert!(
        provider
            .management(
                &uri,
                SessionMode::ReadOnly,
                Authentication::User(Pin::Value(&user))
            )
            .is_err()
    );
    provider
        .management(
            &uri,
            SessionMode::ReadOnly,
            Authentication::User(Pin::Value(&new_user)),
        )
        .unwrap()
        .close()
        .unwrap();
    let new_so = SecretString::from("98765432");
    let mut session = provider
        .management(
            &uri,
            SessionMode::ReadWrite,
            Authentication::SecurityOfficer(Pin::Value(&so)),
        )
        .unwrap();
    session.change_pin(&so, &new_so).unwrap();
    session.close().unwrap();
    provider
        .management(
            &uri,
            SessionMode::ReadWrite,
            Authentication::SecurityOfficer(Pin::Value(&new_so)),
        )
        .unwrap()
        .close()
        .unwrap();
    provider.finalize().unwrap();
}
