// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key transfer policy checks in the disposable client-test token.
use cryptoki::{mechanism::MechanismType, object::KeyType};
use pkcs11_runtime::{
    Attribute, AttributeType, Authentication, Error, KeyOperation, Module, ObjectClass, ObjectRef,
    Pin, SessionMode,
};
use secrecy::SecretString;
#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn key_transfer_enforces_permissions_allowed_mechanisms_trust_and_rw_mode() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let module = Module::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=client-test".parse().unwrap())
        .unwrap();
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    let pin = SecretString::from("12345678");
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    let mut references = Vec::new();
    for (id, wrap, trust_required, allowed) in [
        (0xE0, true, false, MechanismType::AES_KEY_WRAP),
        (0xE1, false, false, MechanismType::AES_KEY_WRAP),
        (0xE2, true, false, MechanismType::AES_CBC),
        (0xE3, true, true, MechanismType::AES_KEY_WRAP),
    ] {
        session
            .create_object(&[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Id(vec![id]),
                Attribute::Label(vec![id]),
                Attribute::Sensitive(true),
                Attribute::Extractable(true),
                Attribute::Wrap(wrap),
                Attribute::Unwrap(true),
                Attribute::WrapWithTrusted(trust_required),
                Attribute::Trusted(false),
                Attribute::AllowedMechanisms(vec![allowed]),
                Attribute::Value(vec![id; 16]),
            ])
            .unwrap();
        references.push(
            ObjectRef::new(
                format!("pkcs11:token=client-test;id=%{id:02X};type=secret-key")
                    .parse()
                    .unwrap(),
            )
            .unwrap(),
        );
    }
    for reference in [&references[1], &references[2]] {
        assert!(matches!(
            session.key_operation_profile(reference, KeyOperation::Wrap),
            Err(Error::UnsupportedKeyOperation)
        ));
    }
    assert!(matches!(
        session.wrap_aes_key(&references[0], &references[0]),
        Err(Error::UnsupportedKeyOperation)
    ));
    assert!(matches!(
        session.wrap_aes_key(&references[0], &references[3]),
        Err(Error::UnsupportedKeyOperation)
    ));
    let wrapped = session
        .wrap_aes_key(&references[0], &references[1])
        .unwrap();
    assert_eq!(wrapped.len(), 24);
    // Permission and parameter rejections do not invoke native crypto or poison the session.
    assert!(matches!(
        session.unwrap_aes_key(&references[0], &wrapped[..23], b"new", b"new"),
        Err(Error::InvalidParameters(_))
    ));
    session.info().unwrap();
    let mut read_only = token.open_session(SessionMode::ReadOnly).unwrap();
    assert!(matches!(
        read_only.unwrap_aes_key(&references[0], &wrapped, b"new", b"new"),
        Err(Error::ReadWriteRequired)
    ));
    read_only.close().unwrap();
    let mut corrupt = wrapped;
    corrupt[0] ^= 1;
    assert!(matches!(
        session.unwrap_aes_key(&references[0], &corrupt, b"new", b"new"),
        Err(Error::Backend { .. })
    ));
    assert!(matches!(session.info(), Err(Error::Closed)));
    session.close().unwrap();
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for reference in references {
        assert!(
            !session
                .resolve(&reference)
                .unwrap()
                .read_attributes(&[AttributeType::Extractable])
                .unwrap()
                .expose_values()
                .is_empty()
        );
        session.resolve(&reference).unwrap().destroy().unwrap();
    }
    assert!(
        session
            .find_objects(&[Attribute::Id(b"new".to_vec())])
            .unwrap()
            .is_empty()
    );
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
