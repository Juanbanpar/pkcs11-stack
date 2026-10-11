// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicitly ignored software-token acceptance; invoke tools/test-softhsm.sh.
#![forbid(unsafe_code)]

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::RvError,
    session::UserType,
};
use pkcs11_locator::Pkcs11Uri;
use pkcs11_runtime::{
    Attribute, AttributeInfo, AttributeType, Authentication, Error, Module, ObjectClass, ObjectRef,
    Pin, SessionMode, SessionState,
};
use secrecy::SecretString;

fn token_uri(serial: &str) -> Pkcs11Uri {
    Pkcs11Uri::builder()
        .path_attribute("serial", serial.as_bytes())
        .unwrap()
        .build()
        .unwrap()
}
fn object_ref(serial: &str, label: &str) -> ObjectRef {
    ObjectRef::new(
        Pkcs11Uri::builder()
            .path_attribute("serial", serial.as_bytes())
            .unwrap()
            .path_attribute("object", label.as_bytes())
            .unwrap()
            .path_attribute("type", b"data")
            .unwrap()
            .build()
            .unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "requires isolated SoftHSM provisioning through tools/test-softhsm.sh"]
fn software_token_runtime_foundation() {
    assert_eq!(
        std::env::var("PKCS11_TEST_ISOLATED").as_deref(),
        Ok("1"),
        "use tools/test-softhsm.sh"
    );
    let path = std::env::var("PKCS11_TEST_MODULE").expect("module from test runner");
    let user = SecretString::from("12345678");
    let so = SecretString::from("87654321");

    // Fixture creation uses cryptoki directly, before the runtime owns lifecycle.
    // No production creation, key generation or cryptographic API is introduced.
    let fixture = Pkcs11::new(&path).unwrap();
    fixture
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slots = fixture.get_slots_with_initialized_token().unwrap();
    assert_eq!(slots.len(), 2);
    let slot = slots[0];
    let serial = fixture
        .get_token_info(slot)
        .unwrap()
        .serial_number()
        .to_owned();
    {
        let session = fixture.open_rw_session(slot).unwrap();
        session.login(UserType::User, Some(&user)).unwrap();
        for (label, private) in [
            ("unique", false),
            ("duplicate", false),
            ("duplicate", false),
            ("private", true),
        ] {
            session
                .create_object(&[
                    Attribute::Class(ObjectClass::DATA),
                    Attribute::Token(true),
                    Attribute::Private(private),
                    Attribute::Label(label.as_bytes().to_vec()),
                    Attribute::Application(b"stage3".to_vec()),
                    Attribute::Value(b"fixture-canary".to_vec()),
                ])
                .unwrap();
        }
        session.close().unwrap();
    }
    fixture.finalize().unwrap();

    let module = Module::load(&path).unwrap();
    assert!(!module.info().manufacturer_id().is_empty());
    assert!(module.path().is_absolute());
    assert!(module.slots(false).unwrap().len() >= 2);
    assert!(module.slots(true).unwrap().len() >= 2);
    assert!(module.slot_info(slot).unwrap().token_present());
    // A rejected second owner must not finalize the first owner's initialization.
    let error = Module::load(&path).unwrap_err();
    assert!(matches!(
        error,
        Error::Backend {
            source: cryptoki::error::Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _),
            ..
        }
    ));
    assert!(module.tokens().is_ok());
    let duplicate: Pkcs11Uri = "pkcs11:token=stage3-test".parse().unwrap();
    assert!(matches!(
        module.resolve_token(duplicate.token_selector()),
        Err(Error::Ambiguous { count: 2, .. })
    ));
    let missing: Pkcs11Uri = "pkcs11:token=absent".parse().unwrap();
    assert!(matches!(
        module.resolve_token(missing.token_selector()),
        Err(Error::NotFound("token"))
    ));
    let selector = token_uri(&serial);
    let token = module.resolve_token(selector.token_selector()).unwrap();
    assert_eq!(token.identity().serial, Some(serial.as_str()));
    let mechanisms = token.mechanisms().unwrap();
    assert!(!mechanisms.is_empty());
    for mechanism in mechanisms.iter().take(3) {
        token.mechanism_info(*mechanism).unwrap();
    }

    let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
    assert!(!ro.info().unwrap().read_write());
    ro.authenticate(Authentication::None).unwrap();
    assert!(matches!(
        ro.authenticate(Authentication::SecurityOfficer(Pin::Value(&so))),
        Err(Error::ReadWriteRequired)
    ));
    assert!(matches!(
        ro.authenticate(Authentication::User(Pin::ProtectedPath)),
        Err(Error::ProtectedPathUnavailable)
    ));
    let bad = SecretString::from("incorrect-fixture-pin");
    let error = ro
        .authenticate(Authentication::User(Pin::Value(&bad)))
        .unwrap_err();
    assert!(!format!("{error:?}").contains("incorrect-fixture-pin"));
    assert!(matches!(
        error,
        Error::Backend {
            source: cryptoki::error::Error::Pkcs11(RvError::PinIncorrect, _),
            ..
        }
    ));
    assert!(matches!(
        ro.resolve(&object_ref(&serial, "private")),
        Err(Error::NotFound("object"))
    ));
    ro.authenticate(Authentication::User(Pin::Value(&user)))
        .unwrap();
    assert!(matches!(
        ro.info().unwrap().session_state(),
        SessionState::RoUser
    ));
    assert!(ro.resolve(&object_ref(&serial, "private")).is_ok());
    assert!(matches!(
        ro.resolve(&object_ref(&serial, "absent")),
        Err(Error::NotFound("object"))
    ));
    assert!(matches!(
        ro.resolve(&object_ref(&serial, "duplicate")),
        Err(Error::Ambiguous { count: 2, .. })
    ));
    let reference = object_ref(&serial, "unique");
    {
        let object = ro.resolve(&reference).unwrap();
        assert!(!format!("{object:?}").contains("fixture-canary"));
        let values = object
            .read_attributes(&[
                AttributeType::Class,
                AttributeType::Label,
                AttributeType::Token,
                AttributeType::Value,
            ])
            .unwrap();
        assert!(
            values
                .expose_values()
                .contains(&Attribute::Label(b"unique".to_vec()))
        );
        assert!(
            values
                .expose_values()
                .contains(&Attribute::Value(b"fixture-canary".to_vec()))
        );
        assert!(!format!("{values:?}").contains(&format!("{:?}", b"fixture-canary".to_vec())));
        let info = object
            .attribute_info(&[AttributeType::Label, AttributeType::PrivateExponent])
            .unwrap();
        assert!(matches!(info[0], AttributeInfo::Available(_)));
        assert!(matches!(info[1], AttributeInfo::TypeInvalid));
    }
    assert_eq!(
        ro.find_objects(&[Attribute::Class(ObjectClass::DATA), Attribute::Token(true)])
            .unwrap()
            .len(),
        4
    );
    let mut rw = token.open_session(SessionMode::ReadWrite).unwrap();
    assert!(rw.info().unwrap().read_write());
    // Closing one session does not issue a disruptive token-wide logout.
    ro.close().unwrap();
    assert!(matches!(
        rw.info().unwrap().session_state(),
        SessionState::RwUser
    ));
    assert!(rw.resolve(&reference).is_ok());
    rw.logout().unwrap();
    assert!(matches!(
        rw.info().unwrap().session_state(),
        SessionState::RwPublic
    ));
    rw.authenticate(Authentication::SecurityOfficer(Pin::Value(&so)))
        .unwrap();
    assert!(matches!(
        rw.info().unwrap().session_state(),
        SessionState::RwSecurityOfficer
    ));
    rw.logout().unwrap();
    rw.close().unwrap();

    // Distinct sessions can run on distinct threads with a shared immutable owner.
    std::thread::scope(|scope| {
        let owner = &module;
        for _ in 0..2 {
            let serial = &serial;
            scope.spawn(move || {
                let selector = token_uri(serial);
                let token = owner.resolve_token(selector.token_selector()).unwrap();
                let session = token.open_session(SessionMode::ReadOnly).unwrap();
                session.info().unwrap();
                session.close().unwrap();
            });
        }
    });
    // Implicit session cleanup precedes explicit module finalization.
    {
        let _session = token.open_session(SessionMode::ReadOnly).unwrap();
    }
    module.finalize().unwrap();
    let module = Module::load(&path).unwrap();
    let token = module.resolve_token(selector.token_selector()).unwrap();
    let mut recreated = token.open_session(SessionMode::ReadOnly).unwrap();
    assert!(recreated.resolve(&reference).is_ok());
    // A reference for a different token cannot resolve just because labels match.
    assert!(matches!(
        recreated.resolve(&object_ref("wrong-serial", "unique")),
        Err(Error::NotFound("object"))
    ));
    recreated.close().unwrap();
    drop(module); // Drop owns finalization too.
    Module::load(&path).unwrap().finalize().unwrap();
}
