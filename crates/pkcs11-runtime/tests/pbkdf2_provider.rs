// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native PBKDF2 outputs compared with OpenSSL without exporting generated values.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::KeyType,
    session::UserType,
};
use pkcs11_runtime::*;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
fn reference(id: &[u8]) -> ObjectRef {
    let id: String = id.iter().map(|b| format!("%{b:02X}")).collect();
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;id={id};type=secret-key")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn expected(digest: &str, password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Vec<u8> {
    let hex = |v: &[u8]| v.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let out = std::process::Command::new(std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap())
        .args([
            "kdf",
            "-binary",
            "-keylen",
            &length.to_string(),
            "-kdfopt",
            &format!("digest:{digest}"),
            "-kdfopt",
            &format!("hexpass:{}", hex(password)),
            "-kdfopt",
            &format!("hexsalt:{}", hex(salt)),
            "-kdfopt",
            &format!("iter:{iterations}"),
            "PBKDF2",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout.len(), length);
    out.stdout
}
#[test]
#[ignore = "requires isolated tools/test-kem-hkdf.sh provider"]
fn pbkdf2_all_sha2_prfs_lengths_binary_inputs_and_openssl_agreement() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let path = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let module = Module::load(&path).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let pin = SecretString::from("12345678");
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    assert!(session.pbkdf2_supported().unwrap());
    let mut proofs = Vec::new();
    for (i, (prf, digest)) in Pbkdf2Prf::ALL
        .into_iter()
        .zip([
            "SHA224",
            "SHA256",
            "SHA384",
            "SHA512",
            "SHA512-224",
            "SHA512-256",
        ])
        .enumerate()
    {
        for (case, output) in [
            Pbkdf2Output::Aes128,
            Pbkdf2Output::Aes192,
            Pbkdf2Output::Aes256,
            Pbkdf2Output::DerivationSecret { length: 1 },
            Pbkdf2Output::DerivationSecret { length: 65 },
            Pbkdf2Output::DerivationSecret { length: 4096 },
        ]
        .into_iter()
        .enumerate()
        {
            let id = if case == 2 {
                vec![0xFA, 0xB0, i as u8]
            } else {
                vec![0xFA, 0xB1, i as u8, case as u8]
            };
            let password = SecretSlice::from(vec![b'p', 0, 0xff, b'\n']);
            let request = Pbkdf2Request {
                password: &password,
                salt: b"salt",
                prf,
                iterations: 2,
                output,
                id: &id,
                label: b"PBKDF2 proof",
            };
            session.generate_pbkdf2(&request).unwrap();
            assert!(matches!(
                session.generate_pbkdf2(&request),
                Err(Error::InvalidParameters(_))
            ));
            let object = session.resolve(&reference(&id)).unwrap();
            let attrs = object
                .read_attributes(&[
                    AttributeType::Class,
                    AttributeType::KeyType,
                    AttributeType::Token,
                    AttributeType::Private,
                    AttributeType::Sensitive,
                    AttributeType::Extractable,
                    AttributeType::Sign,
                    AttributeType::Verify,
                    AttributeType::Wrap,
                    AttributeType::Unwrap,
                    AttributeType::Encrypt,
                    AttributeType::Decrypt,
                    AttributeType::Derive,
                    AttributeType::ValueLen,
                ])
                .unwrap();
            let generic = matches!(output, Pbkdf2Output::DerivationSecret { .. });
            for expected in [
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(if generic {
                    KeyType::GENERIC_SECRET
                } else {
                    KeyType::AES
                }),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(false),
                Attribute::Verify(false),
                Attribute::Wrap(false),
                Attribute::Unwrap(false),
                Attribute::Encrypt(!generic),
                Attribute::Decrypt(!generic),
                Attribute::Derive(generic),
                Attribute::ValueLen(output.length().try_into().unwrap()),
            ] {
                assert!(attrs.expose_values().contains(&expected));
            }
            assert!(matches!(
                object
                    .attribute_info(&[AttributeType::Value])
                    .unwrap()
                    .as_slice(),
                [AttributeInfo::Sensitive]
            ));
            proofs.push((
                id,
                output,
                expected(
                    digest,
                    password.expose_secret(),
                    b"salt",
                    2,
                    output.length(),
                ),
            ));
        }
    }
    for (i, (password, salt, iterations)) in [
        (vec![], vec![1], 1),
        (vec![0xff; 4096], vec![2; 4096], 2),
        (b"passwd".to_vec(), b"salt".to_vec(), 4096),
    ]
    .into_iter()
    .enumerate()
    {
        let password = SecretSlice::from(password);
        let id = vec![0xFA, 0xB2, i as u8];
        let output = Pbkdf2Output::DerivationSecret { length: 65 };
        session
            .generate_pbkdf2(&Pbkdf2Request {
                password: &password,
                salt: &salt,
                iterations,
                prf: Pbkdf2Prf::HmacSha256,
                output,
                id: &id,
                label: b"PBKDF2 boundary",
            })
            .unwrap();
        proofs.push((
            id,
            output,
            expected("SHA256", password.expose_secret(), &salt, iterations, 65),
        ));
    }
    session.close().unwrap();
    module.finalize().unwrap();
    let raw = Pkcs11::new(path).unwrap();
    raw.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = raw
        .get_slots_with_initialized_token()
        .unwrap()
        .into_iter()
        .find(|s| raw.get_token_info(*s).unwrap().label() == "kdf-test")
        .unwrap();
    let s = raw.open_rw_session(slot).unwrap();
    s.login(UserType::User, Some(&pin)).unwrap();
    for (id, output, value) in proofs {
        let keys = s
            .find_objects(&[Attribute::Token(true), Attribute::Id(id.clone())])
            .unwrap();
        assert_eq!(keys.len(), 1);
        let key = keys[0];
        let generic = matches!(output, Pbkdf2Output::DerivationSecret { .. });
        // Only this disposable proof session enables MAC use after checking policy above.
        if generic {
            s.update_attributes(key, &[Attribute::Sign(true)]).unwrap();
        }
        let imported = s
            .create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(if generic {
                    KeyType::GENERIC_SECRET
                } else {
                    KeyType::AES
                }),
                Attribute::Token(false),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(generic),
                Attribute::Encrypt(!generic),
                Attribute::Value(value),
            ])
            .unwrap();
        if generic {
            assert_eq!(
                s.sign(&Mechanism::Sha256Hmac, key, b"proof").unwrap(),
                s.sign(&Mechanism::Sha256Hmac, imported, b"proof").unwrap()
            );
        } else {
            assert_eq!(
                s.encrypt(&Mechanism::AesEcb, key, &[0xA5; 32]).unwrap(),
                s.encrypt(&Mechanism::AesEcb, imported, &[0xA5; 32])
                    .unwrap()
            );
        }
        s.destroy_object(imported).unwrap();
        if !id.starts_with(&[0xFA, 0xB0]) {
            s.destroy_object(key).unwrap();
        }
    }
    s.close().unwrap();
    raw.finalize().unwrap();
}
