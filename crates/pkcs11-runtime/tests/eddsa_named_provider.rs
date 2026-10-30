// SPDX-License-Identifier: MIT OR Apache-2.0
//! All RFC 8032 section 7 vectors and protected curveName provisioning.
#[path = "fixtures/eddsa_named_vectors.rs"]
mod vectors;
use pkcs11_runtime::EdDsaNamedScheme;
use pkcs11_runtime::{
    Attribute, AttributeInfo, AttributeType as A, Authentication, EdDsaCurve,
    EdDsaNamedRequest as Request, EdDsaNamedScheme as Scheme, EdDsaPublicKey, Error, KeyType,
    Module, ObjectClass, ObjectRef, Pin, PrivateKeyRef, PublicKeyRef, SessionMode,
};
use secrecy::SecretString;
fn reference(id: u8, kind: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;id=%D9%ED%01%{id:02X};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn private(id: u8) -> PrivateKeyRef {
    PrivateKeyRef::new(reference(id, "private").uri().to_string().parse().unwrap()).unwrap()
}
fn public(id: u8) -> PublicKeyRef {
    PublicKeyRef::new(reference(id, "public").uri().to_string().parse().unwrap()).unwrap()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store with Edwards support"]
fn rfc8032_schemes_contexts_prehash_and_protected_provisioning() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    let pin = SecretString::from("12345678");
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, vector) in vectors::VECTORS.iter().enumerate() {
        let id = index as u8;
        let curve = vector.scheme.curve();
        // Only these publicly specified test seeds use generic private import.
        session
            .create_object(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::EC_EDWARDS),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
                Attribute::Derive(false),
                Attribute::AlwaysAuthenticate(false),
                Attribute::Id(vec![0xd9, 0xed, 1, id]),
                Attribute::EcParams(curve.named_ec_params().to_vec()),
                Attribute::Value(vectors::hex(vector.private)),
            ])
            .unwrap();
        let key = EdDsaPublicKey::from_bytes(curve, vectors::hex(vector.public)).unwrap();
        session
            .import_named_eddsa_public_key(&key, &[0xd9, 0xed, 1, id], b"RFC8032 public")
            .unwrap();
        assert!(
            session
                .import_named_eddsa_public_key(&key, &[0xd9, 0xed, 1, id], b"duplicate")
                .is_err()
        );
        assert_eq!(
            session
                .named_eddsa_public_key(&public(id))
                .unwrap()
                .as_bytes(),
            vectors::hex(vector.public)
        );
        let object = session.resolve(&reference(id, "public")).unwrap();
        let attrs = object
            .read_attributes(&[A::Trusted, A::Verify, A::Derive, A::Private])
            .unwrap();
        for attr in [
            Attribute::Trusted(false),
            Attribute::Verify(true),
            Attribute::Derive(false),
            Attribute::Private(false),
        ] {
            assert!(attrs.expose_values().contains(&attr));
        }
        let message = vectors::hex(vector.message);
        let context = vectors::hex(vector.context);
        let request = Request {
            scheme: vector.scheme,
            message: &message,
            context: &context,
        };
        let signature = session
            .sign_named_eddsa(&private(id), &request, None)
            .unwrap();
        assert_eq!(
            signature,
            vectors::hex(vector.signature),
            "RFC vector {index}/{:?}",
            vector.scheme
        );
        session
            .verify_named_eddsa(&public(id), &request, &signature)
            .unwrap();
        let mut bad_message = message.clone();
        bad_message.push(0);
        assert!(matches!(
            session.verify_named_eddsa(
                &public(id),
                &Request {
                    message: &bad_message,
                    ..request
                },
                &signature
            ),
            Err(Error::SignatureMismatch)
        ));
        if vector.scheme != Scheme::Ed25519 {
            let mut bad_context = context.clone();
            bad_context.push(0);
            assert!(matches!(
                session.verify_named_eddsa(
                    &public(id),
                    &Request {
                        context: &bad_context,
                        ..request
                    },
                    &signature
                ),
                Err(Error::SignatureMismatch)
            ));
        }
        session.info().unwrap();
    }
    for (id, curve) in [(0x80, EdDsaCurve::Ed25519), (0x81, EdDsaCurve::Ed448)] {
        session
            .generate_named_eddsa_key_pair(curve, &[0xd9, 0xed, 1, id], b"generated RFC8032", false)
            .unwrap();
        assert!(
            session
                .generate_named_eddsa_key_pair(curve, &[0xd9, 0xed, 1, id], b"duplicate", false)
                .is_err()
        );
        let raw = session.named_eddsa_public_key(&public(id)).unwrap();
        assert_eq!(raw.as_bytes().len(), curve.public_key_length());
        let attrs = session.resolve(&reference(id, "private")).unwrap();
        let values = attrs
            .read_attributes(&[
                A::Sensitive,
                A::Extractable,
                A::Sign,
                A::Derive,
                A::EcParams,
                A::Local,
            ])
            .unwrap();
        for attr in [
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Derive(false),
            Attribute::EcParams(curve.named_ec_params().to_vec()),
            Attribute::Local(true),
        ] {
            assert!(values.expose_values().contains(&attr));
        }
        assert!(matches!(
            attrs.attribute_info(&[A::Value]).unwrap().as_slice(),
            [AttributeInfo::Sensitive]
        ));
        for scheme in [
            Scheme::Ed25519,
            Scheme::Ed25519ctx,
            Scheme::Ed25519ph,
            Scheme::Ed448,
            Scheme::Ed448ph,
        ] {
            if scheme.curve() != curve {
                continue;
            }
            let request = Request {
                scheme,
                message: b"generated named agreement",
                context: if scheme == Scheme::Ed25519 {
                    &[]
                } else {
                    &[0xa5; 255]
                },
            };
            let signature = session
                .sign_named_eddsa(&private(id), &request, None)
                .unwrap();
            session
                .verify_named_eddsa(&public(id), &request, &signature)
                .unwrap();
        }
    }
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
