// SPDX-License-Identifier: MIT OR Apache-2.0
//! Live SHA-512 HashML-DSA permissions and protected key metadata.
use pkcs11_runtime::*;
use secrecy::SecretString;
use sha2::{Digest, Sha512};

#[test]
#[ignore = "requires tools/test-kem-hkdf.sh with ML-DSA enabled"]
fn hash_ml_dsa_runtime_modes_permissions_and_domain_separation() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let pin = SecretString::from("12345678");
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, parameter_set) in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ]
    .into_iter()
    .enumerate()
    {
        let private = PrivateKeyRef::new(
            format!("pkcs11:token=kdf-test;id=%E0%{index:02X};type=private")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let public = PublicKeyRef::new(
            format!("pkcs11:token=kdf-test;id=%E0%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        session
            .generate_ml_dsa_key_pair(
                parameter_set,
                &[0xE0, index as u8],
                b"HashML-DSA runtime",
                index == 1,
            )
            .unwrap();
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
        for attr in [AttributeType::Value, AttributeType::Seed] {
            assert!(matches!(
                object.attribute_info(&[attr]).unwrap().as_slice(),
                [AttributeInfo::Sensitive]
            ));
        }
        let message = b"HashML-DSA runtime message";
        let digest: [u8; 64] = Sha512::digest(message).into();
        let policy = MlDsaSigningPolicy::default();
        let context_pin = || (index == 1).then_some(Pin::Value(&pin));
        for input in [
            HashMlDsaInput::Message(message),
            HashMlDsaInput::Sha512Digest(&digest),
        ] {
            let request = HashMlDsaRequest {
                parameter_set,
                input,
                context: b"runtime",
                hedging: MlDsaHedging::Deterministic,
            };
            let caps = session
                .hash_ml_dsa_capabilities(&private, input.mode())
                .unwrap();
            assert!(caps.can_sign);
            let signature = session
                .sign_hash_ml_dsa(&private, &request, &policy, context_pin())
                .unwrap();
            session
                .verify_hash_ml_dsa(&public, &request, &signature)
                .unwrap();
            let pure = MlDsaRequest {
                parameter_set,
                message,
                context: request.context,
                hedging: request.hedging,
            };
            assert!(matches!(
                session.verify_ml_dsa(&public, &pure, &signature),
                Err(Error::SignatureMismatch)
            ));
            let changed = HashMlDsaRequest {
                context: b"wrong",
                ..request
            };
            assert!(matches!(
                session.verify_hash_ml_dsa(&public, &changed, &signature),
                Err(Error::SignatureMismatch)
            ));
            session
                .verify_hash_ml_dsa(&public, &request, &signature)
                .unwrap();
        }
        session
            .resolve(private.as_object_ref())
            .unwrap()
            .update_attributes(&[Attribute::Sign(false)])
            .unwrap();
        for mode in [HashMlDsaMode::Message, HashMlDsaMode::Prehashed] {
            assert!(
                !session
                    .hash_ml_dsa_capabilities(&private, mode)
                    .unwrap()
                    .can_sign
            );
        }
        session
            .resolve(public.as_object_ref())
            .unwrap()
            .update_attributes(&[Attribute::Verify(false)])
            .unwrap();
        let request = HashMlDsaRequest {
            parameter_set,
            input: HashMlDsaInput::Message(message),
            context: b"",
            hedging: MlDsaHedging::Required,
        };
        assert!(matches!(
            session.sign_hash_ml_dsa(&private, &request, &policy, context_pin()),
            Err(Error::UnsupportedSigning(_))
        ));
        assert!(matches!(
            session.verify_hash_ml_dsa(
                &public,
                &request,
                &vec![0; parameter_set.signature_length()]
            ),
            Err(Error::UnsupportedSigning(_))
        ));
        session.info().unwrap();
    }
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
