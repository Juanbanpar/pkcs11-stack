// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed ML-KEM operations against the disposable required PQC provider.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::KeyType,
    session::UserType,
    types::AuthPin,
};
use pkcs11_runtime::{
    Attribute, AttributeInfo, AttributeType, Authentication, Error, MlKemOperation,
    MlKemParameterSet, MlKemRequest, Module, ObjectClass, ObjectRef, Pin, PrivateKeyRef,
    PublicKeyRef, SessionMode,
};
use secrecy::SecretString;

fn public(index: usize) -> PublicKeyRef {
    PublicKeyRef::new(
        format!("pkcs11:token=pqc-test;id=%E1%{index:02X};type=public")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn private(index: usize) -> PrivateKeyRef {
    PrivateKeyRef::new(
        format!("pkcs11:token=pqc-test;id=%E1%{index:02X};type=private")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn secret(index: usize, direction: u8) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token=pqc-test;id=%E2%{index:02X}%{direction:02X};type=secret-key")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
#[test]
#[ignore = "requires tools/test-ml-kem.sh"]
fn typed_ml_kem_permissions_outputs_and_secret_agreement() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let path = std::env::var_os("PKCS11_TEST_MODULE").unwrap();
    let module = Module::load(&path).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=pqc-test".parse().unwrap())
        .unwrap();
    let parameters = [
        MlKemParameterSet::MlKem512,
        MlKemParameterSet::MlKem768,
        MlKemParameterSet::MlKem1024,
    ];
    assert_eq!(token.ml_kem_generation_options().unwrap(), parameters);
    let pin = SecretString::from("12345678");
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, parameter) in parameters.into_iter().enumerate() {
        session
            .generate_ml_kem_key_pair(parameter, &[0xE1, index as u8], b"typed ML-KEM")
            .unwrap();
        let public = public(index);
        let private = private(index);
        let capabilities = session
            .ml_kem_capabilities(public.as_object_ref(), MlKemOperation::Encapsulate)
            .unwrap();
        assert_eq!(capabilities.parameter_set, parameter);
        assert_eq!(capabilities.operation, MlKemOperation::Encapsulate);
        assert_eq!(
            session
                .ml_kem_capabilities(private.as_object_ref(), MlKemOperation::Decapsulate)
                .unwrap()
                .parameter_set,
            parameter
        );
        assert!(matches!(
            session.ml_kem_capabilities(public.as_object_ref(), MlKemOperation::Decapsulate),
            Err(Error::UnsupportedKeyOperation)
        ));
        let object = session.resolve(private.as_object_ref()).unwrap();
        let attrs = object
            .read_attributes(&[AttributeType::Sensitive, AttributeType::Extractable])
            .unwrap();
        assert!(attrs.expose_values().contains(&Attribute::Sensitive(true)));
        assert!(
            attrs
                .expose_values()
                .contains(&Attribute::Extractable(false))
        );
        for attribute in [AttributeType::Value, AttributeType::Seed] {
            assert!(matches!(
                object.attribute_info(&[attribute]).unwrap().as_slice(),
                [AttributeInfo::Sensitive]
            ));
        }
        let sender = MlKemRequest {
            parameter_set: parameter,
            id: &[0xE2, index as u8, 1],
            label: b"sender",
        };
        let receiver = MlKemRequest {
            id: &[0xE2, index as u8, 2],
            label: b"receiver",
            ..sender
        };
        let altered = MlKemRequest {
            id: &[0xE2, index as u8, 3],
            label: b"altered",
            ..sender
        };
        let wrong = MlKemRequest {
            parameter_set: parameters[(index + 1) % 3],
            ..sender
        };
        assert!(matches!(
            session.encapsulate_ml_kem(&public, &wrong),
            Err(Error::UnsupportedKeyOperation)
        ));
        assert!(
            session
                .find_objects(&[Attribute::Id(sender.id.to_vec())])
                .unwrap()
                .is_empty()
        );
        session
            .resolve(public.as_object_ref())
            .unwrap()
            .update_attributes(&[Attribute::Encapsulate(false)])
            .unwrap();
        assert!(matches!(
            session.encapsulate_ml_kem(&public, &sender),
            Err(Error::UnsupportedKeyOperation)
        ));
        session
            .resolve(public.as_object_ref())
            .unwrap()
            .update_attributes(&[Attribute::Encapsulate(true)])
            .unwrap();
        // Export remains valid when encapsulation is disabled on the source object.
        session
            .resolve(public.as_object_ref())
            .unwrap()
            .update_attributes(&[Attribute::Encapsulate(false)])
            .unwrap();
        let exported = session.ml_kem_public_key(&public).unwrap();
        assert_eq!(exported.parameter_set(), parameter);
        let imported = PublicKeyRef::new(
            format!("pkcs11:token=pqc-test;id=%E4%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        session
            .import_ml_kem_public_key(&exported, &[0xE4, index as u8], b"imported peer")
            .unwrap();
        assert_eq!(
            session.ml_kem_public_key(&imported).unwrap().as_bytes(),
            exported.as_bytes()
        );
        session
            .resolve(public.as_object_ref())
            .unwrap()
            .update_attributes(&[Attribute::Encapsulate(true)])
            .unwrap();
        let ciphertext = session.encapsulate_ml_kem(&imported, &sender).unwrap();
        assert_eq!(ciphertext.len(), parameter.ciphertext_length());
        assert!(matches!(
            session.encapsulate_ml_kem(&public, &sender),
            Err(Error::InvalidParameters(_))
        ));
        for length in [0, ciphertext.len() - 1, ciphertext.len() + 1] {
            assert!(matches!(
                session.decapsulate_ml_kem(&private, &receiver, &vec![0; length]),
                Err(Error::InvalidParameters(_))
            ));
        }
        session
            .resolve(private.as_object_ref())
            .unwrap()
            .update_attributes(&[Attribute::Decapsulate(false)])
            .unwrap();
        assert!(matches!(
            session.decapsulate_ml_kem(&private, &receiver, &ciphertext),
            Err(Error::UnsupportedKeyOperation)
        ));
        session
            .resolve(private.as_object_ref())
            .unwrap()
            .update_attributes(&[Attribute::Decapsulate(true)])
            .unwrap();
        session
            .decapsulate_ml_kem(&private, &receiver, &ciphertext)
            .unwrap();
        assert!(matches!(
            session.decapsulate_ml_kem(&private, &receiver, &ciphertext),
            Err(Error::InvalidParameters(_))
        ));
        let mut changed = ciphertext;
        changed[0] ^= 1;
        session
            .decapsulate_ml_kem(&private, &altered, &changed)
            .unwrap();
        for direction in 1..=3 {
            let object = session.resolve(&secret(index, direction)).unwrap();
            let attrs = object
                .read_attributes(&[
                    AttributeType::Class,
                    AttributeType::KeyType,
                    AttributeType::ValueLen,
                    AttributeType::Private,
                    AttributeType::Sensitive,
                    AttributeType::Extractable,
                    AttributeType::Token,
                    AttributeType::Derive,
                    AttributeType::Encrypt,
                    AttributeType::Decrypt,
                    AttributeType::Sign,
                    AttributeType::Verify,
                    AttributeType::Wrap,
                    AttributeType::Unwrap,
                ])
                .unwrap();
            for attr in [
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::ValueLen(32.into()),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Token(true),
                Attribute::Derive(true),
                Attribute::Encrypt(false),
                Attribute::Decrypt(false),
                Attribute::Sign(false),
                Attribute::Verify(false),
                Attribute::Wrap(false),
                Attribute::Unwrap(false),
            ] {
                assert!(attrs.expose_values().contains(&attr), "missing {attr:?}");
            }
            assert!(matches!(
                object
                    .attribute_info(&[AttributeType::Value])
                    .unwrap()
                    .as_slice(),
                [AttributeInfo::Sensitive]
            ));
        }
        let public_value = session
            .resolve(public.as_object_ref())
            .unwrap()
            .read_attributes(&[AttributeType::Value, AttributeType::ParameterSet])
            .unwrap();
        let mut restricted = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::ML_KEM),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Id(vec![0xE3, index as u8]),
            Attribute::Encapsulate(true),
            Attribute::AllowedMechanisms(vec![pkcs11_runtime::MechanismType::ML_KEM_KEY_PAIR_GEN]),
        ];
        let mut private_public = restricted.clone();
        private_public.retain(|attr| !matches!(attr, Attribute::Private(_) | Attribute::Id(_)));
        private_public.extend([
            Attribute::Private(true),
            Attribute::Id(vec![0xE5, index as u8]),
        ]);
        private_public.extend(public_value.expose_values().iter().cloned());
        session.create_object(&private_public).unwrap();
        let hidden = PublicKeyRef::new(
            format!("pkcs11:token=pqc-test;id=%E5%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            session.ml_kem_public_key(&hidden),
            Err(Error::UnsupportedKeyOperation)
        ));
        // Duplicate IDs are never silently overwritten or arbitrarily selected.
        session
            .import_ml_kem_public_key(&exported, &[0xE4, index as u8], b"duplicate")
            .unwrap();
        assert!(matches!(
            session.ml_kem_public_key(&imported),
            Err(Error::Ambiguous { count: 2, .. })
        ));
        restricted.extend(public_value.expose_values().iter().cloned());
        session.create_object(&restricted).unwrap();
        let restricted = PublicKeyRef::new(
            format!("pkcs11:token=pqc-test;id=%E3%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            session.ml_kem_capabilities(restricted.as_object_ref(), MlKemOperation::Encapsulate),
            Err(Error::UnsupportedKeyOperation)
        ));
    }
    session.close().unwrap();
    let mut read_only = token.open_session(SessionMode::ReadOnly).unwrap();
    let request = MlKemRequest {
        parameter_set: parameters[0],
        id: b"read-only",
        label: b"read-only",
    };
    assert!(matches!(
        read_only.encapsulate_ml_kem(&public(0), &request),
        Err(Error::ReadWriteRequired)
    ));
    assert!(matches!(
        read_only.decapsulate_ml_kem(
            &private(0),
            &request,
            &vec![0; parameters[0].ciphertext_length()]
        ),
        Err(Error::ReadWriteRequired)
    ));
    assert!(matches!(
        read_only.generate_ml_kem_key_pair(parameters[0], b"ro", b"ro"),
        Err(Error::ReadWriteRequired)
    ));
    let exported = read_only.ml_kem_public_key(&public(0)).unwrap();
    assert!(matches!(
        read_only.import_ml_kem_public_key(&exported, b"read-only", b"peer"),
        Err(Error::ReadWriteRequired)
    ));
    assert!(matches!(
        read_only.import_ml_kem_public_key(&exported, b"", b"peer"),
        Err(Error::InvalidParameters(_))
    ));
    read_only.close().unwrap();
    module.finalize().unwrap();
    // Use a separate lifecycle owner only after runtime finalization. Tests enable
    // HMAC on these disposable objects to compare full secrets without extracting them.
    let module = Pkcs11::new(path).unwrap();
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = module
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|&slot| module.get_token_info(slot).unwrap().label() == "pqc-test")
        .unwrap();
    let session = module.open_rw_session(slot).unwrap();
    session
        .login(UserType::User, Some(&AuthPin::new("12345678".into())))
        .unwrap();
    for index in 0..3 {
        let mut tags = vec![];
        for direction in 1..=3 {
            let objects = session
                .find_objects(&[
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::Id(vec![0xE2, index, direction]),
                ])
                .unwrap();
            assert_eq!(objects.len(), 1);
            let object = objects[0];
            session
                .update_attributes(object, &[Attribute::Sign(true)])
                .unwrap();
            tags.push(
                session
                    .sign(
                        &Mechanism::Sha256Hmac,
                        object,
                        b"ML-KEM secret agreement challenge",
                    )
                    .unwrap(),
            );
            session
                .update_attributes(object, &[Attribute::Sign(false)])
                .unwrap();
        }
        assert_eq!(tags[0].len(), 32);
        assert_eq!(tags[0], tags[1]);
        assert_ne!(tags[0], tags[2]);
    }
    session.close().unwrap();
    module.finalize().unwrap();
}
