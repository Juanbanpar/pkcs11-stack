// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native-provider prerequisite for token-side HKDF; no application HKDF API is implied.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{
        Mechanism, MechanismType,
        hkdf::{HkdfParams, HkdfSalt},
    },
    object::{Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass},
    session::Session,
};

fn template(length: usize) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Token(false),
        Attribute::Private(false),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Derive(false),
        Attribute::Sign(true),
        Attribute::Verify(false),
        Attribute::Encrypt(false),
        Attribute::Decrypt(false),
        Attribute::Wrap(false),
        Attribute::Unwrap(false),
        Attribute::ValueLen(length.try_into().unwrap()),
    ]
}
fn imported_template(bytes: &[u8], derive: bool) -> Vec<Attribute> {
    let mut attrs = template(bytes.len());
    attrs.retain(|attr| {
        !matches!(
            attr,
            Attribute::ValueLen(_) | Attribute::Derive(_) | Attribute::Sign(_)
        )
    });
    attrs.extend([
        Attribute::Value(bytes.to_vec()),
        Attribute::Derive(derive),
        Attribute::Sign(!derive),
    ]);
    attrs
}
fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn check_vector(session: &Session, salt: HkdfSalt<'_>, info: &[u8], expected: &[u8]) {
    let base = session
        .create_object(&imported_template(&[0x0B; 22], true))
        .unwrap();
    let derive = |info| {
        session
            .derive_key(
                &Mechanism::HkdfDerive(HkdfParams::new(
                    MechanismType::SHA256,
                    Some(salt),
                    Some(info),
                )),
                base,
                &template(expected.len()),
            )
            .unwrap()
    };
    let derived = derive(info);
    let known = session
        .create_object(&imported_template(expected, false))
        .unwrap();
    let challenge = b"HKDF known-answer comparison";
    let expected_tag = session
        .sign(&Mechanism::Sha256Hmac, known, challenge)
        .unwrap();
    assert_eq!(
        session
            .sign(&Mechanism::Sha256Hmac, derived, challenge)
            .unwrap(),
        expected_tag
    );
    assert!(matches!(
        session
            .get_attribute_info(derived, &[AttributeType::Value])
            .unwrap()
            .as_slice(),
        [AttributeInfo::Sensitive]
    ));
    let attrs = session
        .get_attributes(
            derived,
            &[
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::Token,
                AttributeType::ValueLen,
            ],
        )
        .unwrap();
    for required in [
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Token(false),
        Attribute::ValueLen(expected.len().try_into().unwrap()),
    ] {
        assert!(attrs.contains(&required));
    }
    let changed = derive(b"different protocol context");
    assert_ne!(
        session
            .sign(&Mechanism::Sha256Hmac, changed, challenge)
            .unwrap(),
        expected_tag
    );
    for object in [changed, known, derived, base] {
        session.destroy_object(object).unwrap();
    }
}
#[test]
#[ignore = "requires tools/test-hkdf.sh and an NSS softoken module"]
fn rfc5869_sha256_sensitive_session_keys() {
    assert_eq!(
        std::env::var("PKCS11_TEST_HKDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = Pkcs11::new(std::env::var_os("PKCS11_TEST_HKDF_MODULE").unwrap()).unwrap();
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = module
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|slot| {
            module
                .get_mechanism_list(*slot)
                .unwrap()
                .contains(&MechanismType::HKDF_DERIVE)
        })
        .expect("provider must advertise CKM_HKDF_DERIVE");
    assert!(
        module
            .get_mechanism_info(slot, MechanismType::HKDF_DERIVE)
            .unwrap()
            .derive()
    );
    let session = module.open_ro_session(slot).unwrap();
    // RFC 5869 Appendix A, SHA-256 cases 1 and 3. All inputs are public test data.
    check_vector(
        &session,
        HkdfSalt::Data(&hex("000102030405060708090a0b0c")),
        &hex("f0f1f2f3f4f5f6f7f8f9"),
        &hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
    );
    check_vector(
        &session,
        HkdfSalt::Null,
        &[],
        &hex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
    );
    session.close().unwrap();
    module.finalize().unwrap();
}
