// SPDX-License-Identifier: MIT OR Apache-2.0
//! Generated ECDH/AES permissions and key use on the disposable client-test token.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{KeyType, ObjectHandle},
    session::UserType,
};
use pkcs11_runtime::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, Attribute, AttributeInfo, AttributeType,
    Authentication, EcdhDerivation, EcdhKeyPairRequest, Error, KeyOperation, Module, NamedCurve,
    ObjectClass, ObjectRef, Pin, SessionMode,
};
use secrecy::SecretString;
fn reference(id: &[u8], kind: &str) -> ObjectRef {
    let id: String = id.iter().map(|b| format!("%{b:02X}")).collect();
    ObjectRef::new(
        format!("pkcs11:token=client-test;id={id};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn inspect(object: &pkcs11_runtime::Object<'_, '_>, expected: &[Attribute]) {
    let types: Vec<_> = expected.iter().map(Attribute::attribute_type).collect();
    let attrs = object.read_attributes(&types).unwrap();
    for attribute in expected {
        assert!(attrs.expose_values().contains(attribute));
    }
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable token"]
fn generation_permissions_ecdh_agreement_and_aes_key_use() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let path = std::env::var_os("PKCS11_TEST_MODULE").unwrap();
    let module = Module::load(&path).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=client-test".parse().unwrap())
        .unwrap();
    let curves = [NamedCurve::P256, NamedCurve::P384, NamedCurve::P521];
    let sizes = [
        AesKeySize::Bits128,
        AesKeySize::Bits192,
        AesKeySize::Bits256,
    ];
    assert_eq!(token.ecdh_generation_options().unwrap(), curves);
    assert_eq!(token.aes_generation_options().unwrap(), sizes);
    let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
    assert!(matches!(
        ro.generate_ecdh_key_pair(&EcdhKeyPairRequest {
            curve: NamedCurve::P256,
            id: b"ro",
            label: b"ro"
        }),
        Err(Error::ReadWriteRequired)
    ));
    assert!(matches!(
        ro.generate_aes_key(&AesKeyRequest {
            size: AesKeySize::Bits128,
            purpose: AesKeyPurpose::Encryption,
            id: b"ro",
            label: b"ro"
        }),
        Err(Error::ReadWriteRequired)
    ));
    ro.close().unwrap();
    let pin = SecretString::from("12345678");
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, curve) in curves.into_iter().enumerate() {
        let mut points = vec![];
        for side in 0..2 {
            let id = [0x91, index as u8, side];
            let req = EcdhKeyPairRequest {
                curve,
                id: &id,
                label: b"generated agreement key",
            };
            {
                let (public, private) = session.generate_ecdh_key_pair(&req).unwrap();
                inspect(
                    &public,
                    &[
                        Attribute::Class(ObjectClass::PUBLIC_KEY),
                        Attribute::KeyType(KeyType::EC),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::Verify(false),
                        Attribute::Encrypt(false),
                        Attribute::Wrap(false),
                        Attribute::Derive(false),
                        Attribute::Local(true),
                    ],
                );
                inspect(
                    &private,
                    &[
                        Attribute::Class(ObjectClass::PRIVATE_KEY),
                        Attribute::KeyType(KeyType::EC),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Extractable(false),
                        Attribute::Sign(false),
                        Attribute::Decrypt(false),
                        Attribute::Unwrap(false),
                        Attribute::Derive(true),
                        Attribute::AlwaysAuthenticate(false),
                        Attribute::AlwaysSensitive(true),
                        Attribute::NeverExtractable(true),
                        Attribute::Local(true),
                    ],
                );
                assert!(matches!(
                    private
                        .attribute_info(&[AttributeType::Value])
                        .unwrap()
                        .as_slice(),
                    [AttributeInfo::Sensitive]
                ));
                let attrs = public.read_attributes(&[AttributeType::EcPoint]).unwrap();
                let [Attribute::EcPoint(point)] = attrs.expose_values() else {
                    panic!("missing public point")
                };
                // These generated named-curve fixtures use short-form DER, except P-521.
                let (prefix, length) = if curve == NamedCurve::P521 {
                    (vec![4, 0x81, 133], 133)
                } else if curve == NamedCurve::P384 {
                    (vec![4, 97], 97)
                } else {
                    (vec![4, 65], 65)
                };
                let point = point.strip_prefix(prefix.as_slice()).unwrap();
                assert_eq!(point.len(), length);
                assert_eq!(point[0], 4);
                points.push(point.to_vec());
            }
            assert!(matches!(
                session.generate_ecdh_key_pair(&req),
                Err(Error::InvalidParameters(_))
            ));
            session.info().unwrap();
        }
        for side in 0..2 {
            let base = reference(&[0x91, index as u8, side], "private");
            session
                .derive_ecdh_secret(
                    &base,
                    &EcdhDerivation {
                        curve,
                        peer: &points[1 - side as usize],
                        id: &[0x92, index as u8, side],
                        label: b"generated shared secret",
                    },
                )
                .unwrap();
        }
    }
    // A key-pair ID collision in either class is rejected before creating the other half.
    for (index, class) in [ObjectClass::PUBLIC_KEY, ObjectClass::PRIVATE_KEY]
        .into_iter()
        .enumerate()
    {
        let id = [0x90, index as u8];
        let (a, b) = session
            .generate_ecdh_key_pair(&EcdhKeyPairRequest {
                curve: NamedCurve::P256,
                id: &id,
                label: b"partial pair",
            })
            .unwrap();
        if class == ObjectClass::PUBLIC_KEY {
            b.destroy().unwrap();
        } else {
            a.destroy().unwrap();
        }
        assert!(matches!(
            session.generate_ecdh_key_pair(&EcdhKeyPairRequest {
                curve: NamedCurve::P256,
                id: &id,
                label: b"collision"
            }),
            Err(Error::InvalidParameters(_))
        ));
        assert_eq!(
            session
                .find_objects(&[Attribute::Token(true), Attribute::Id(id.to_vec())])
                .unwrap()
                .len(),
            1
        );
    }
    for (index, size) in sizes.into_iter().enumerate() {
        for (purpose_index, purpose) in [AesKeyPurpose::Encryption, AesKeyPurpose::Wrapping]
            .into_iter()
            .enumerate()
        {
            let id = [0x93, index as u8, purpose_index as u8];
            let req = AesKeyRequest {
                size,
                purpose,
                id: &id,
                label: b"generated AES key",
            };
            let encryption = purpose == AesKeyPurpose::Encryption;
            {
                let key = session.generate_aes_key(&req).unwrap();
                inspect(
                    &key,
                    &[
                        Attribute::Class(ObjectClass::SECRET_KEY),
                        Attribute::KeyType(KeyType::AES),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Extractable(false),
                        Attribute::Local(true),
                        Attribute::AlwaysSensitive(true),
                        Attribute::NeverExtractable(true),
                        Attribute::ValueLen(size.length().try_into().unwrap()),
                        Attribute::Encrypt(encryption),
                        Attribute::Decrypt(encryption),
                        Attribute::Wrap(!encryption),
                        Attribute::Unwrap(!encryption),
                        Attribute::Derive(false),
                        Attribute::Sign(false),
                        Attribute::Verify(false),
                    ],
                );
                assert!(matches!(
                    key.attribute_info(&[AttributeType::Value])
                        .unwrap()
                        .as_slice(),
                    [AttributeInfo::Sensitive]
                ));
            }
            assert!(matches!(
                session.generate_aes_key(&req),
                Err(Error::InvalidParameters(_))
            ));
            let key = reference(&id, "secret-key");
            if encryption {
                assert!(matches!(
                    session.key_operation_profile(&key, KeyOperation::Wrap),
                    Err(Error::UnsupportedKeyOperation)
                ));
            } else {
                let target = [0x95, index as u8];
                session
                    .create_object(&[
                        Attribute::Class(ObjectClass::SECRET_KEY),
                        Attribute::KeyType(KeyType::AES),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Extractable(true),
                        Attribute::WrapWithTrusted(false),
                        Attribute::Encrypt(true),
                        Attribute::Id(target.to_vec()),
                        Attribute::Value(vec![0xA5; 16]),
                    ])
                    .unwrap();
                let wrapped = session
                    .wrap_aes_key(&key, &reference(&target, "secret-key"))
                    .unwrap();
                assert_eq!(wrapped.len(), 24);
                session
                    .unwrap_aes_key(
                        &key,
                        &wrapped,
                        &[0x94, index as u8],
                        b"generated wrapper output",
                    )
                    .unwrap();
                // Nonextractability is retained even for the encryption-only generated target.
                assert!(matches!(
                    session.wrap_aes_key(&key, &reference(&[0x93, index as u8, 0], "secret-key")),
                    Err(Error::UnsupportedKeyOperation)
                ));
            }
        }
    }
    session.close().unwrap();
    module.finalize().unwrap();
    let module = Pkcs11::new(&path).unwrap();
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = module
        .get_slots_with_initialized_token()
        .unwrap()
        .into_iter()
        .find(|slot| module.get_token_info(*slot).unwrap().label() == "client-test")
        .unwrap();
    let session = module.open_rw_session(slot).unwrap();
    session.login(UserType::User, Some(&pin)).unwrap();
    let find = |id: &[u8]| -> ObjectHandle {
        let keys = session
            .find_objects(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::Id(id.to_vec()),
            ])
            .unwrap();
        assert_eq!(keys.len(), 1);
        keys[0]
    };
    for index in 0..3 {
        let tag = |side| {
            let key = find(&[0x92, index, side]);
            session
                .update_attributes(key, &[Attribute::Sign(true)])
                .unwrap();
            let tag = session
                .sign(&Mechanism::Sha256Hmac, key, b"agreement challenge")
                .unwrap();
            session
                .update_attributes(key, &[Attribute::Sign(false)])
                .unwrap();
            tag
        };
        assert_eq!(tag(0), tag(1));
        let key = find(&[0x93, index, 0]);
        let challenge = [0x42; 32];
        let ciphertext = session
            .encrypt(&Mechanism::AesEcb, key, &challenge)
            .unwrap();
        assert_eq!(
            session
                .decrypt(&Mechanism::AesEcb, key, &ciphertext)
                .unwrap(),
            challenge
        );
        assert_eq!(
            session
                .encrypt(&Mechanism::AesEcb, find(&[0x95, index]), &challenge)
                .unwrap(),
            session
                .encrypt(&Mechanism::AesEcb, find(&[0x94, index]), &challenge)
                .unwrap()
        );
    }
    session.close().unwrap();
    module.finalize().unwrap();
}
