// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native counter-mode KDF compared with the independent OpenSSL KBKDF implementation.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::KeyType,
    session::UserType,
};
use pkcs11_runtime::{
    Attribute, AttributeType, Authentication, DigestAlgorithm, Error, KbkdfOutput, KbkdfRequest,
    MechanismType, Module, ObjectClass, ObjectRef, Pin, SessionMode,
};
use secrecy::SecretString;
fn reference(id: &[u8]) -> ObjectRef {
    let id: String = id.iter().map(|b| format!("%{b:02X}")).collect();
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;id={id};type=secret-key")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn base(id: &[u8], kind: KeyType, length: usize) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(kind),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Derive(true),
        Attribute::Sign(false),
        Attribute::Verify(false),
        Attribute::Encrypt(false),
        Attribute::Decrypt(false),
        Attribute::Wrap(false),
        Attribute::Unwrap(false),
        Attribute::AllowedMechanisms(vec![MechanismType::SP800_108_COUNTER_KDF]),
        Attribute::Id(id.to_vec()),
        Attribute::Value(vec![0x0B; length]),
    ]
}
fn expected(
    digest: DigestAlgorithm,
    key_length: usize,
    output: KbkdfOutput,
    label: &[u8],
    context: &[u8],
) -> Vec<u8> {
    let hex = |v: &[u8]| v.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut cmd = std::process::Command::new(std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap());
    cmd.args([
        "kdf",
        "-binary",
        "-keylen",
        &output.length().to_string(),
        "-kdfopt",
        "mode:COUNTER",
        "-kdfopt",
        "mac:HMAC",
        "-kdfopt",
        match digest {
            DigestAlgorithm::Sha256 => "digest:SHA256",
            DigestAlgorithm::Sha384 => "digest:SHA384",
            DigestAlgorithm::Sha512 => "digest:SHA512",
        },
        "-kdfopt",
        &format!("hexkey:{}", hex(&vec![0x0B; key_length])),
        "-kdfopt",
        "use-l:1",
        "-kdfopt",
        "use-separator:1",
    ]);
    if !label.is_empty() {
        cmd.args(["-kdfopt", &format!("hexsalt:{}", hex(label))]);
    }
    if !context.is_empty() {
        cmd.args(["-kdfopt", &format!("hexinfo:{}", hex(context))]);
    }
    let out = cmd.arg("KBKDF").output().unwrap();
    assert!(
        out.status.success(),
        "OpenSSL KBKDF: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout.len(), output.length());
    out.stdout
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh with the SP800-108 Kryoptic build"]
fn counter_kdf_openssl_outputs_key_types_permissions_and_bounds() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let path = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let module = Module::load(&path).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    assert!(
        token
            .mechanisms()
            .unwrap()
            .contains(&MechanismType::SP800_108_COUNTER_KDF),
        "rebuild the provider with tools/build-kem-hkdf-provider.sh"
    );
    let pin = SecretString::from("12345678");
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    let mut proofs = vec![];
    for (index, (digest, kind)) in [
        (DigestAlgorithm::Sha256, KeyType::SHA256_HMAC),
        (DigestAlgorithm::Sha384, KeyType::SHA384_HMAC),
        (DigestAlgorithm::Sha512, KeyType::SHA512_HMAC),
    ]
    .into_iter()
    .enumerate()
    {
        for (typed, kind) in [(false, KeyType::GENERIC_SECRET), (true, kind)] {
            let key_length = if typed { digest.output_len() } else { 31 };
            let id = [0xFA, 0x80, index as u8, u8::from(typed)];
            session.create_object(&base(&id, kind, key_length)).unwrap();
            let key = reference(&id);
            let caps = session.kbkdf_capabilities(&key).unwrap();
            assert_eq!(caps.input_length, key_length);
            for candidate in [
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
            ] {
                assert_eq!(caps.supports(candidate), !typed || candidate == digest);
                if !caps.supports(candidate) {
                    assert!(matches!(
                        session.derive_kbkdf(
                            &key,
                            &KbkdfRequest {
                                digest: candidate,
                                kdf_label: b"label",
                                context: b"ctx",
                                output: KbkdfOutput::Aes256,
                                id: b"wrong-prf",
                                label: b"wrong"
                            }
                        ),
                        Err(Error::UnsupportedKeyOperation)
                    ));
                    session.info().unwrap();
                }
            }
            for (case, output) in [
                KbkdfOutput::Aes128,
                KbkdfOutput::Aes192,
                KbkdfOutput::Aes256,
                KbkdfOutput::DerivationSecret { length: 1 },
                KbkdfOutput::DerivationSecret { length: 33 },
                KbkdfOutput::DerivationSecret { length: 128 },
                KbkdfOutput::DerivationSecret { length: 4096 },
            ]
            .into_iter()
            .enumerate()
            {
                let id = [0xFA, 0x81, index as u8, u8::from(typed), case as u8];
                let long = vec![0xA5; 4096];
                let (label, context) = match case % 4 {
                    0 => (&[][..], &[][..]),
                    1 => (b"label\0binary".as_slice(), b"\xFFcontext\0".as_slice()),
                    2 => (long.as_slice(), long.as_slice()),
                    _ => (&[][..], b"context".as_slice()),
                };
                let request = KbkdfRequest {
                    digest,
                    kdf_label: label,
                    context,
                    output,
                    id: &id,
                    label: b"counter output",
                };
                session.derive_kbkdf(&key, &request).unwrap();
                let object = session.resolve(&reference(&id)).unwrap();
                let attrs = object
                    .read_attributes(&[
                        AttributeType::Class,
                        AttributeType::KeyType,
                        AttributeType::ValueLen,
                        AttributeType::Private,
                        AttributeType::Sensitive,
                        AttributeType::Extractable,
                        AttributeType::Derive,
                        AttributeType::Sign,
                        AttributeType::Verify,
                        AttributeType::Encrypt,
                        AttributeType::Decrypt,
                        AttributeType::Wrap,
                        AttributeType::Unwrap,
                    ])
                    .unwrap();
                let aes = !matches!(output, KbkdfOutput::DerivationSecret { .. });
                for attr in [
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(if aes {
                        KeyType::AES
                    } else {
                        KeyType::GENERIC_SECRET
                    }),
                    Attribute::ValueLen(output.length().try_into().unwrap()),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Derive(!aes),
                    Attribute::Encrypt(aes),
                    Attribute::Decrypt(aes),
                    Attribute::Sign(false),
                    Attribute::Verify(false),
                    Attribute::Wrap(false),
                    Attribute::Unwrap(false),
                ] {
                    assert!(attrs.expose_values().contains(&attr));
                }
                assert!(matches!(
                    object
                        .attribute_info(&[AttributeType::Value])
                        .unwrap()
                        .as_slice(),
                    [pkcs11_runtime::AttributeInfo::Sensitive]
                ));
                proofs.push((
                    id.to_vec(),
                    output,
                    expected(digest, key_length, output, label, context),
                ));
                assert!(matches!(
                    session.derive_kbkdf(&key, &request),
                    Err(Error::InvalidParameters(_))
                ));
            }
            session.resolve(&key).unwrap().destroy().unwrap();
        }
        let id = [0xFA, 0x82, index as u8];
        let request = KbkdfRequest {
            digest,
            kdf_label: b"application",
            context: b"v1 context",
            output: KbkdfOutput::Aes256,
            id: &id,
            label: b"counter canonical AES",
        };
        session
            .derive_kbkdf(&reference(&[0xA0, index as u8]), &request)
            .unwrap();
        proofs.push((
            id.to_vec(),
            request.output,
            expected(
                digest,
                digest.output_len(),
                request.output,
                request.kdf_label,
                request.context,
            ),
        ));
    }
    for (case, bad) in [
        Attribute::Derive(false),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
        Attribute::AllowedMechanisms(vec![MechanismType::HKDF_DERIVE]),
        Attribute::KeyType(KeyType::HKDF),
        Attribute::Value(vec![0x0B; 15]),
        Attribute::Value(vec![0x0B; 4097]),
    ]
    .into_iter()
    .enumerate()
    {
        let id = [0xFA, 0x83, case as u8];
        let mut attrs = base(&id, KeyType::GENERIC_SECRET, 32);
        let kind = bad.attribute_type();
        *attrs
            .iter_mut()
            .find(|a| a.attribute_type() == kind)
            .unwrap() = bad;
        session.create_object(&attrs).unwrap();
        assert!(matches!(
            session.kbkdf_capabilities(&reference(&id)),
            Err(Error::UnsupportedKeyOperation)
        ));
        assert!(matches!(
            session.derive_kbkdf(
                &reference(&id),
                &KbkdfRequest {
                    digest: DigestAlgorithm::Sha256,
                    kdf_label: b"label",
                    context: b"ctx",
                    output: KbkdfOutput::Aes256,
                    id: b"policy-output",
                    label: b"policy"
                }
            ),
            Err(Error::UnsupportedKeyOperation)
        ));
        session.info().unwrap();
        session.resolve(&reference(&id)).unwrap().destroy().unwrap();
    }
    for length in [16, 4096] {
        let id = [0xFA, 0x84, (length == 4096) as u8];
        session
            .create_object(&base(&id, KeyType::GENERIC_SECRET, length))
            .unwrap();
        let request = KbkdfRequest {
            digest: DigestAlgorithm::Sha256,
            kdf_label: b"bounds",
            context: &[],
            output: KbkdfOutput::Aes256,
            id: &[0xFA, 0x85, (length == 4096) as u8],
            label: b"base bounds",
        };
        session.derive_kbkdf(&reference(&id), &request).unwrap();
        proofs.push((
            request.id.to_vec(),
            request.output,
            expected(
                request.digest,
                length,
                request.output,
                request.kdf_label,
                request.context,
            ),
        ));
        session.resolve(&reference(&id)).unwrap().destroy().unwrap();
    }
    let request = KbkdfRequest {
        digest: DigestAlgorithm::Sha256,
        kdf_label: &[],
        context: &[],
        output: KbkdfOutput::Aes256,
        id: b"ro-output",
        label: b"ro-output",
    };
    let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
    assert!(matches!(
        ro.derive_kbkdf(&reference(&[0xA0, 0]), &request),
        Err(Error::ReadWriteRequired)
    ));
    ro.close().unwrap();
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
    let raw = Pkcs11::new(&path).unwrap();
    raw.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = raw.get_slots_with_initialized_token().unwrap()[0];
    let session = raw.open_rw_session(slot).unwrap();
    session.login(UserType::User, Some(&pin)).unwrap();
    for (id, output, value) in proofs {
        let keys = session
            .find_objects(&[Attribute::Token(true), Attribute::Id(id.clone())])
            .unwrap();
        assert_eq!(keys.len(), 1);
        let key = keys[0];
        let generic = matches!(output, KbkdfOutput::DerivationSecret { .. });
        if generic {
            session
                .update_attributes(key, &[Attribute::Sign(true)])
                .unwrap();
        }
        let imported = session
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
                session.sign(&Mechanism::Sha256Hmac, key, b"proof").unwrap(),
                session
                    .sign(&Mechanism::Sha256Hmac, imported, b"proof")
                    .unwrap()
            );
        } else {
            assert_eq!(
                session
                    .encrypt(&Mechanism::AesEcb, key, &[0xA5; 32])
                    .unwrap(),
                session
                    .encrypt(&Mechanism::AesEcb, imported, &[0xA5; 32])
                    .unwrap()
            );
        }
        session.destroy_object(imported).unwrap();
        if !id.starts_with(&[0xFA, 0x82]) {
            session.destroy_object(key).unwrap();
        }
    }
    session.close().unwrap();
    raw.finalize().unwrap();
}
