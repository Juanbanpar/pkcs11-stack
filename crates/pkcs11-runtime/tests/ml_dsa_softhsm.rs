// SPDX-License-Identifier: MIT OR Apache-2.0
//! ML-DSA runtime execution against the required disposable PQC provider.
use pkcs11_runtime::{
    Attribute, AttributeInfo, AttributeType, Authentication, Error, MechanismType, MlDsaHedging,
    MlDsaParameterSet, MlDsaRequest, MlDsaSigningPolicy, Module, Pin, PrivateKeyRef, PublicKeyRef,
    SessionMode,
};
use secrecy::SecretString;

#[test]
#[ignore = "requires PKCS11_TEST_REQUIRE_PQC=1 tools/test-softhsm.sh"]
fn ml_dsa_runtime_permissions_context_and_authentication() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    assert_eq!(std::env::var("PKCS11_TEST_REQUIRE_PQC").as_deref(), Ok("1"));
    let module = Module::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=pqc-test".parse().unwrap())
        .unwrap();
    let parameters = [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ];
    assert_eq!(token.ml_dsa_generation_options().unwrap(), parameters);
    let pin = SecretString::from("12345678");
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    session
        .generate_signing_key_pair(
            pkcs11_runtime::KeyKind::Ec(pkcs11_runtime::NamedCurve::P256),
            b"classical",
            b"classical",
            false,
        )
        .unwrap();
    let classical = PrivateKeyRef::new(
        "pkcs11:token=pqc-test;object=classical;type=private"
            .parse()
            .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        session.ml_dsa_capabilities(&classical),
        Err(Error::UnsupportedSigning(_))
    ));
    session
        .resolve(classical.as_object_ref())
        .unwrap()
        .destroy()
        .unwrap();
    assert!(matches!(
        session.generate_ml_dsa_key_pair(parameters[0], b"", b"invalid", false),
        Err(Error::InvalidParameters(_))
    ));
    for (index, parameter) in parameters.into_iter().enumerate() {
        let always_authenticate = index == 1;
        let id = [0xD1, index as u8];
        let private = PrivateKeyRef::new(
            format!("pkcs11:token=pqc-test;id=%D1%{index:02X};type=private")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let public = PublicKeyRef::new(
            format!("pkcs11:token=pqc-test;id=%D1%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        session
            .generate_ml_dsa_key_pair(parameter, &id, b"runtime ML-DSA", always_authenticate)
            .unwrap();
        let caps = session.ml_dsa_capabilities(&private).unwrap();
        assert_eq!(caps.parameter_set, parameter);
        assert_eq!(caps.always_authenticate, always_authenticate);
        assert!(caps.can_sign);
        let key = session.resolve(private.as_object_ref()).unwrap();
        let attributes = key
            .read_attributes(&[AttributeType::Sensitive, AttributeType::Extractable])
            .unwrap();
        assert!(
            attributes
                .expose_values()
                .contains(&Attribute::Sensitive(true))
        );
        assert!(
            attributes
                .expose_values()
                .contains(&Attribute::Extractable(false))
        );
        for kind in [AttributeType::Value, AttributeType::Seed] {
            assert!(matches!(
                key.attribute_info(&[kind]).unwrap().as_slice(),
                [AttributeInfo::Sensitive]
            ));
        }
        let public_material = session.ml_dsa_public_key(&public).unwrap();
        assert_eq!(public_material.parameter_set(), parameter);
        assert_eq!(
            public_material.as_bytes().len(),
            parameter.public_key_length()
        );
        let policy = MlDsaSigningPolicy::default();
        let request = MlDsaRequest {
            parameter_set: parameter,
            message: b"runtime ML-DSA message",
            context: b"runtime-context",
            hedging: MlDsaHedging::Required,
        };
        let context_pin = || always_authenticate.then_some(Pin::Value(&pin));
        if always_authenticate {
            assert!(matches!(
                session.sign_ml_dsa(&private, &request, &policy, None),
                Err(Error::ContextAuthenticationRequired)
            ));
        } else {
            assert!(matches!(
                session.sign_ml_dsa(&private, &request, &policy, Some(Pin::Value(&pin))),
                Err(Error::InvalidParameters(_))
            ));
        }
        let wrong_parameter = MlDsaRequest {
            parameter_set: parameters[(index + 1) % 3],
            ..request
        };
        assert!(matches!(
            session.sign_ml_dsa(&private, &wrong_parameter, &policy, context_pin()),
            Err(Error::UnsupportedSigning(_))
        ));
        assert!(matches!(
            session.sign_ml_dsa(
                &private,
                &request,
                &MlDsaSigningPolicy {
                    parameter_sets: vec![]
                },
                context_pin()
            ),
            Err(Error::UnsupportedSigning(_))
        ));
        for context in [b"".as_slice(), &[0xA5; 255]] {
            let request = MlDsaRequest {
                context,
                message: if context.is_empty() {
                    b""
                } else {
                    request.message
                },
                ..request
            };
            let signature = session
                .sign_ml_dsa(&private, &request, &policy, context_pin())
                .unwrap();
            assert_eq!(signature.len(), parameter.signature_length());
            session
                .verify_ml_dsa(&public, &request, &signature)
                .unwrap();
            for changed in [
                MlDsaRequest {
                    message: b"changed",
                    ..request
                },
                MlDsaRequest {
                    context: b"changed",
                    ..request
                },
            ] {
                assert!(matches!(
                    session.verify_ml_dsa(&public, &changed, &signature),
                    Err(Error::SignatureMismatch)
                ));
                session
                    .verify_ml_dsa(&public, &request, &signature)
                    .unwrap();
            }
            assert!(matches!(
                session.verify_ml_dsa(&public, &request, &signature[..signature.len() - 1]),
                Err(Error::SignatureMismatch)
            ));
            session.info().unwrap();
        }
        let deterministic = MlDsaRequest {
            hedging: MlDsaHedging::Deterministic,
            ..request
        };
        let a = session
            .sign_ml_dsa(&private, &deterministic, &policy, context_pin())
            .unwrap();
        let b = session
            .sign_ml_dsa(&private, &deterministic, &policy, context_pin())
            .unwrap();
        assert_eq!(a, b);
        assert!(matches!(
            session.sign_ml_dsa(
                &private,
                &MlDsaRequest {
                    context: &[0; 256],
                    ..request
                },
                &policy,
                context_pin()
            ),
            Err(Error::InvalidParameters(_))
        ));
        // Permission rejections occur before signing and leave the session healthy.
        session
            .resolve(private.as_object_ref())
            .unwrap()
            .update_attributes(&[Attribute::Sign(false)])
            .unwrap();
        assert!(!session.ml_dsa_capabilities(&private).unwrap().can_sign);
        assert!(matches!(
            session.sign_ml_dsa(&private, &request, &policy, context_pin()),
            Err(Error::UnsupportedSigning(_))
        ));
        // SoftHSM's allowed-mechanism list is immutable: set it at public-key import.
        let parameter_attribute = match parameter {
            MlDsaParameterSet::MlDsa44 => cryptoki::object::MlDsaParameterSetType::ML_DSA_44,
            MlDsaParameterSet::MlDsa65 => cryptoki::object::MlDsaParameterSetType::ML_DSA_65,
            MlDsaParameterSet::MlDsa87 => cryptoki::object::MlDsaParameterSetType::ML_DSA_87,
        };
        session
            .create_object(&[
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Class(pkcs11_runtime::ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(cryptoki::object::KeyType::ML_DSA),
                Attribute::Id(vec![0xD2]),
                Attribute::ParameterSet(parameter_attribute.into()),
                Attribute::Value(public_material.as_bytes().to_vec()),
                Attribute::Verify(true),
                Attribute::AllowedMechanisms(vec![MechanismType::HASH_ML_DSA]),
            ])
            .unwrap();
        let restricted =
            PublicKeyRef::new("pkcs11:token=pqc-test;id=%D2;type=public".parse().unwrap()).unwrap();
        assert!(matches!(
            session.verify_ml_dsa(&restricted, &request, &a),
            Err(Error::UnsupportedSigning(_))
        ));
        session
            .resolve(restricted.as_object_ref())
            .unwrap()
            .destroy()
            .unwrap();
        session
            .resolve(public.as_object_ref())
            .unwrap()
            .update_attributes(&[Attribute::Verify(false)])
            .unwrap();
        assert!(matches!(
            session.verify_ml_dsa(&public, &request, &a),
            Err(Error::UnsupportedSigning(_))
        ));
        let mut read_only = token.open_session(SessionMode::ReadOnly).unwrap();
        assert!(matches!(
            read_only.generate_ml_dsa_key_pair(parameter, b"read-only", b"invalid", false),
            Err(Error::ReadWriteRequired)
        ));
        read_only.close().unwrap();
        session
            .resolve(private.as_object_ref())
            .unwrap()
            .destroy()
            .unwrap();
        session
            .resolve(public.as_object_ref())
            .unwrap()
            .destroy()
            .unwrap();
    }
    // A failed context login invalidates the operation and cannot be retried on the session.
    session
        .generate_ml_dsa_key_pair(parameters[0], b"bad-context", b"bad-context", true)
        .unwrap();
    let private = PrivateKeyRef::new(
        "pkcs11:token=pqc-test;object=bad-context;type=private"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let wrong_pin = SecretString::from("incorrect");
    let request = MlDsaRequest {
        parameter_set: parameters[0],
        message: b"message",
        context: b"",
        hedging: MlDsaHedging::Required,
    };
    assert!(matches!(
        session.sign_ml_dsa(
            &private,
            &request,
            &MlDsaSigningPolicy::default(),
            Some(Pin::Value(&wrong_pin))
        ),
        Err(Error::Backend { .. })
    ));
    assert!(matches!(session.info(), Err(Error::Closed)));
    session.close().unwrap();
    module.finalize().unwrap();
}
