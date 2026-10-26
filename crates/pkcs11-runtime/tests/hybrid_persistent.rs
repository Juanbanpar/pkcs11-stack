// SPDX-License-Identifier: MIT OR Apache-2.0
//! P-256 || ML-KEM-768 agreement, policy and cleanup on a disposable token.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{KeyType, ObjectHandle},
    session::{Session as NativeSession, UserType},
};
use pkcs11_runtime::{
    Attribute, AttributeType, Authentication, DigestAlgorithm, EcdhDerivation, EcdhKeyPairRequest,
    Error, HkdfOutput, HkdfRequest, MechanismType, MlKemParameterSet, MlKemRequest, Module,
    NamedCurve, ObjectClass, ObjectRef, Pin, PrivateKeyRef, PublicKeyRef, SessionMode,
};
use secrecy::SecretString;

fn path() -> std::ffi::OsString {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()
}
fn native() -> (Pkcs11, NativeSession) {
    let module = Pkcs11::new(path()).unwrap();
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = module.get_slots_with_initialized_token().unwrap()[0];
    let session = module.open_rw_session(slot).unwrap();
    session
        .login(UserType::User, Some(&SecretString::from("12345678")))
        .unwrap();
    (module, session)
}
fn reference(id: &[u8], kind: &str) -> ObjectRef {
    let id: String = id.iter().map(|byte| format!("%{byte:02X}")).collect();
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;id={id};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn secret(id: &[u8]) -> ObjectRef {
    reference(id, "secret-key")
}
fn request(id: &[u8]) -> HkdfRequest<'_> {
    HkdfRequest {
        digest: DigestAlgorithm::Sha512,
        salt: b"public test salt",
        info: b"application v1 peers A B transcript",
        output: HkdfOutput::Aes256,
        id,
        label: b"hybrid application key",
    }
}
fn base(id: &[u8], value: Vec<u8>) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Derive(true),
        Attribute::Id(id.to_vec()),
        Attribute::Value(value),
    ]
}
fn find(session: &NativeSession, id: &[u8]) -> ObjectHandle {
    let keys = session
        .find_objects(&[
            Attribute::Token(true),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Id(id.to_vec()),
        ])
        .unwrap();
    assert_eq!(keys.len(), 1);
    keys[0]
}
fn encrypted(session: &NativeSession, id: &[u8]) -> Vec<u8> {
    session
        .encrypt(&Mechanism::AesEcb, find(session, id), &[0xA5; 32])
        .unwrap()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn token_hybrid_construction_and_policy() {
    let module = Module::load(path()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&SecretString::from(
            "12345678",
        ))))
        .unwrap();
    let mut peers = vec![];
    for index in 0..2 {
        let (public, _) = session
            .generate_ecdh_key_pair(&EcdhKeyPairRequest {
                curve: NamedCurve::P256,
                id: &[0xF0, index],
                label: b"hybrid agreement peer",
            })
            .unwrap();
        let attrs = public.read_attributes(&[AttributeType::EcPoint]).unwrap();
        let [Attribute::EcPoint(point)] = attrs.expose_values() else {
            panic!("missing public point")
        };
        let point = point.strip_prefix(&[4, 65]).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 4);
        peers.push(point.to_vec());
    }
    for index in 0..2 {
        session
            .derive_ecdh_secret(
                &reference(&[0xF0, index], "private"),
                &EcdhDerivation {
                    curve: NamedCurve::P256,
                    peer: &peers[1 - index as usize],
                    id: &[0xF1, index],
                    label: b"classical component",
                },
            )
            .unwrap();
    }
    session
        .generate_ml_kem_key_pair(MlKemParameterSet::MlKem768, &[0xF2], b"hybrid recipient")
        .unwrap();
    let public = PublicKeyRef::new(
        reference(&[0xF2], "public")
            .uri()
            .to_string()
            .parse()
            .unwrap(),
    )
    .unwrap();
    let private = PrivateKeyRef::new(
        reference(&[0xF2], "private")
            .uri()
            .to_string()
            .parse()
            .unwrap(),
    )
    .unwrap();
    let ciphertext = session
        .encapsulate_ml_kem(
            &public,
            &MlKemRequest {
                parameter_set: MlKemParameterSet::MlKem768,
                id: &[0xF3, 0],
                label: b"PQ sender",
            },
        )
        .unwrap();
    session
        .decapsulate_ml_kem(
            &private,
            &MlKemRequest {
                parameter_set: MlKemParameterSet::MlKem768,
                id: &[0xF3, 1],
                label: b"PQ receiver",
            },
            &ciphertext,
        )
        .unwrap();
    let mut altered = ciphertext;
    altered[0] ^= 1;
    session
        .decapsulate_ml_kem(
            &private,
            &MlKemRequest {
                parameter_set: MlKemParameterSet::MlKem768,
                id: &[0xF3, 2],
                label: b"altered PQ component",
            },
            &altered,
        )
        .unwrap();
    let temporary_count = session
        .find_objects(&[Attribute::Token(false)])
        .unwrap()
        .len();
    for index in 0..7 {
        let id = [0xF4, index];
        let mut req = request(&id);
        if index == 2 || index == 3 {
            req.output = HkdfOutput::DerivationSecret { length: 42 };
        }
        if index == 4 {
            req.info = b"different context";
        }
        let classical = secret(&[0xF1, index % 2]);
        let pq = secret(&[0xF3, if index == 6 { 2 } else { index % 2 }]);
        let (a, b) = if index == 5 {
            (&pq, &classical)
        } else {
            (&classical, &pq)
        };
        session.derive_hybrid_hkdf(a, b, &req).unwrap();
        assert_eq!(
            session
                .find_objects(&[Attribute::Token(false)])
                .unwrap()
                .len(),
            temporary_count
        );
        let attrs = session
            .resolve(&secret(&id))
            .unwrap()
            .read_attributes(&[
                AttributeType::Private,
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::Derive,
                AttributeType::Encrypt,
                AttributeType::ValueLen,
            ])
            .unwrap();
        for expected in [
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Derive(index == 2 || index == 3),
            Attribute::Encrypt(index != 2 && index != 3),
            Attribute::ValueLen(req.output.length().try_into().unwrap()),
        ] {
            assert!(attrs.expose_values().contains(&expected));
        }
        assert!(matches!(
            session.derive_hybrid_hkdf(a, b, &req),
            Err(Error::InvalidParameters(_))
        ));
    }
    let a = secret(&[0xF1, 0]);
    let b = secret(&[0xF3, 0]);
    assert!(matches!(
        session.derive_hybrid_hkdf(&a, &a, &request(b"same")),
        Err(Error::UnsupportedKeyOperation)
    ));
    for (index, replacement) in [
        Attribute::Derive(false),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
        Attribute::AllowedMechanisms(vec![MechanismType::HKDF_DERIVE]),
        Attribute::Value(vec![0; 31]),
    ]
    .into_iter()
    .enumerate()
    {
        let id = [0xF5, index as u8];
        let mut attrs = base(&id, vec![0; 32]);
        attrs.retain(|attr| attr.attribute_type() != replacement.attribute_type());
        attrs.push(replacement);
        session.create_object(&attrs).unwrap();
        for (first, second) in [(&secret(&id), &b), (&a, &secret(&id))] {
            assert!(
                session
                    .derive_hybrid_hkdf(first, second, &request(b"rejected"))
                    .is_err()
            );
            assert!(
                session
                    .find_objects(&[Attribute::Id(b"rejected".to_vec())])
                    .unwrap()
                    .is_empty()
            );
        }
    }
    // Public test inputs allow comparison with an independent HKDF implementation.
    session
        .create_object(&base(&[0xF6, 0], vec![0x0B; 32]))
        .unwrap();
    session
        .create_object(&base(&[0xF6, 1], vec![0xA5; 32]))
        .unwrap();
    session
        .derive_hybrid_hkdf(&secret(&[0xF6, 0]), &secret(&[0xF6, 1]), &request(&[0xF7]))
        .unwrap();
    session.close().unwrap();
    let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
    assert!(matches!(
        ro.derive_hybrid_hkdf(&a, &b, &request(b"read-only")),
        Err(Error::ReadWriteRequired)
    ));
    ro.close().unwrap();
    module.finalize().unwrap();
    let (module, session) = native();
    assert_eq!(
        encrypted(&session, &[0xF4, 0]),
        encrypted(&session, &[0xF4, 1])
    );
    assert_ne!(
        encrypted(&session, &[0xF4, 0]),
        encrypted(&session, &[0xF4, 4])
    );
    assert_ne!(
        encrypted(&session, &[0xF4, 0]),
        encrypted(&session, &[0xF4, 5])
    );
    assert_ne!(
        encrypted(&session, &[0xF4, 0]),
        encrypted(&session, &[0xF4, 6])
    );
    let mac = |index| {
        let key = find(&session, &[0xF4, index]);
        session
            .update_attributes(key, &[Attribute::Sign(true)])
            .unwrap();
        let tag = session
            .sign(&Mechanism::Sha256Hmac, key, b"hybrid agreement challenge")
            .unwrap();
        session
            .update_attributes(key, &[Attribute::Sign(false)])
            .unwrap();
        tag
    };
    assert_eq!(mac(2), mac(3));
    let hex = |value: &[u8]| {
        value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let result = std::process::Command::new(std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap())
        .args([
            "kdf",
            "-binary",
            "-keylen",
            "32",
            "-kdfopt",
            "digest:SHA512",
            "-kdfopt",
            &format!("hexkey:{}{}", hex(&[0x0B; 32]), hex(&[0xA5; 32])),
            "-kdfopt",
            &format!("hexsalt:{}", hex(request(&[0xF7]).salt)),
            "-kdfopt",
            &format!("hexinfo:{}", hex(request(&[0xF7]).info)),
            "HKDF",
        ])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(result.stdout.len(), 32);
    let expected = session
        .create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Token(false),
            Attribute::Encrypt(true),
            Attribute::Value(result.stdout),
        ])
        .unwrap();
    assert_eq!(
        encrypted(&session, &[0xF7]),
        session
            .encrypt(&Mechanism::AesEcb, expected, &[0xA5; 32])
            .unwrap()
    );
    session.destroy_object(expected).unwrap();
    session.close().unwrap();
    module.finalize().unwrap();
}
#[test]
#[ignore = "runs after CLI derivation in tools/test-kem-hkdf.sh"]
fn cli_derived_keys_match() {
    let (module, session) = native();
    for index in 0..3 {
        assert_eq!(
            encrypted(&session, &[0xD3, index, 0]),
            encrypted(&session, &[0xD3, index, 1])
        );
    }
    assert_eq!(
        encrypted(&session, &[0xD4, 0]),
        encrypted(&session, &[0xD4, 1])
    );
    assert_ne!(
        encrypted(&session, &[0xD4, 0]),
        encrypted(&session, &[0xD4, 2])
    );
    session.close().unwrap();
    module.finalize().unwrap();
}
