// SPDX-License-Identifier: MIT OR Apache-2.0
//! Provider compatibility tests; these do not expose PQC through the runtime API.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Function, Pkcs11},
    error::{Error, RvError},
    mechanism::{
        Mechanism, MechanismType,
        dsa::{HedgeType, SignAdditionalContext},
    },
    object::{
        Attribute, AttributeInfo, AttributeType, KeyType, MlDsaParameterSetType,
        MlKemParameterSetType, ObjectClass,
    },
    session::{Session, UserType},
    types::AuthPin,
};

fn nonextractable(session: &Session, key: cryptoki::object::ObjectHandle) {
    let attributes = session
        .get_attributes(key, &[AttributeType::Sensitive, AttributeType::Extractable])
        .unwrap();
    assert!(attributes.contains(&Attribute::Sensitive(true)));
    assert!(attributes.contains(&Attribute::Extractable(false)));
    assert!(matches!(
        session
            .get_attribute_info(key, &[AttributeType::Value])
            .unwrap()
            .as_slice(),
        [AttributeInfo::Sensitive]
    ));
    assert!(
        session
            .get_attributes(key, &[AttributeType::Value])
            .unwrap()
            .is_empty()
    );
}

#[test]
#[ignore = "requires PKCS11_TEST_REQUIRE_PQC=1 tools/test-softhsm.sh"]
fn required_pqc_provider_operations() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    assert_eq!(std::env::var("PKCS11_TEST_REQUIRE_PQC").as_deref(), Ok("1"));
    let module = Pkcs11::new(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slots: Vec<_> = module
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .filter(|&slot| module.get_token_info(slot).unwrap().label() == "pqc-test")
        .collect();
    assert_eq!(slots.len(), 1);
    let slot = slots[0];
    for function in [Function::EncapsulateKey, Function::DecapsulateKey] {
        assert!(module.is_fn_supported(function), "missing {function:?}");
    }
    let mechanisms = module.get_mechanism_list(slot).unwrap();
    for mechanism in [
        MechanismType::ML_DSA_KEY_PAIR_GEN,
        MechanismType::ML_DSA,
        MechanismType::ML_KEM_KEY_PAIR_GEN,
        MechanismType::ML_KEM,
    ] {
        assert!(mechanisms.contains(&mechanism), "missing {mechanism:?}");
    }
    let session = module.open_rw_session(slot).unwrap();
    session
        .login(UserType::User, Some(&AuthPin::new("12345678".into())))
        .unwrap();
    for (parameter, signature_length) in [
        (MlDsaParameterSetType::ML_DSA_44, 2420),
        (MlDsaParameterSetType::ML_DSA_65, 3309),
        (MlDsaParameterSetType::ML_DSA_87, 4627),
    ] {
        let (public, private) = session
            .generate_key_pair(
                &Mechanism::MlDsaKeyPairGen,
                &[
                    Attribute::Token(false),
                    Attribute::ParameterSet(parameter.into()),
                    Attribute::Verify(true),
                ],
                &[
                    Attribute::Token(false),
                    Attribute::Private(true),
                    Attribute::Sign(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                ],
            )
            .unwrap();
        nonextractable(&session, private);
        for context in [None, Some(b"pkcs11-stack-pqc-test".as_slice())] {
            let mechanism =
                Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Preferred, context));
            let signature = session
                .sign(&mechanism, private, b"provider compatibility")
                .unwrap();
            assert_eq!(signature.len(), signature_length);
            session
                .verify(&mechanism, public, b"provider compatibility", &signature)
                .unwrap();
            let wrong_context = Mechanism::MlDsa(SignAdditionalContext::new(
                HedgeType::Preferred,
                Some(b"different context"),
            ));
            assert!(matches!(
                session.verify(
                    &wrong_context,
                    public,
                    b"provider compatibility",
                    &signature
                ),
                Err(Error::Pkcs11(RvError::SignatureInvalid, _))
            ));
            assert!(matches!(
                session.verify(&mechanism, public, b"modified message", &signature),
                Err(Error::Pkcs11(RvError::SignatureInvalid, _))
            ));
        }
        session.destroy_object(private).unwrap();
        session.destroy_object(public).unwrap();
    }
    for (parameter, ciphertext_length) in [
        (MlKemParameterSetType::ML_KEM_512, 768),
        (MlKemParameterSetType::ML_KEM_768, 1088),
        (MlKemParameterSetType::ML_KEM_1024, 1568),
    ] {
        let (public, private) = session
            .generate_key_pair(
                &Mechanism::MlKemKeyPairGen,
                &[
                    Attribute::Token(false),
                    Attribute::ParameterSet(parameter.into()),
                    Attribute::Encapsulate(true),
                ],
                &[
                    Attribute::Token(false),
                    Attribute::Private(true),
                    Attribute::Decapsulate(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                ],
            )
            .unwrap();
        nonextractable(&session, private);
        let template = [
            Attribute::Token(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ];
        let (ciphertext, sender) = session
            .encapsulate_key(&Mechanism::MlKem, public, &template)
            .unwrap();
        assert_eq!(ciphertext.len(), ciphertext_length);
        let recipient = session
            .decapsulate_key(&Mechanism::MlKem, private, &template, &ciphertext)
            .unwrap();
        nonextractable(&session, sender);
        nonextractable(&session, recipient);
        // One-block AES is only a test for equality of the two token-held secrets.
        let message = [0xA5; 16];
        let encrypted = session
            .encrypt(&Mechanism::AesEcb, sender, &message)
            .unwrap();
        assert_eq!(
            session
                .decrypt(&Mechanism::AesEcb, recipient, &encrypted)
                .unwrap(),
            message
        );
        assert!(
            session
                .decapsulate_key(
                    &Mechanism::MlKem,
                    private,
                    &template,
                    &ciphertext[..ciphertext.len() - 1]
                )
                .is_err()
        );
        for key in [sender, recipient, private, public] {
            session.destroy_object(key).unwrap();
        }
    }
    session.close().unwrap();
    module.finalize().unwrap();
}
