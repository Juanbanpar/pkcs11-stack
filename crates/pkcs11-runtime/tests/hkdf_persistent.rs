// SPDX-License-Identifier: MIT OR Apache-2.0
//! Persistent HKDF and ML-KEM -> HKDF on one disposable provider.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::KeyType,
    session::UserType,
};
use pkcs11_runtime::{
    Attribute, AttributeInfo, AttributeType, Authentication, DigestAlgorithm, Error, HkdfOutput,
    HkdfRequest, MlKemParameterSet, MlKemRequest, Module, ObjectClass, ObjectRef, Pin,
    PrivateKeyRef, PublicKeyRef, Session, SessionMode,
};
use secrecy::SecretString;

fn reference(id: &[u8], kind: &str) -> ObjectRef {
    let id: String = id.iter().map(|byte| format!("%{byte:02X}")).collect();
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;id={id};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn request<'a>(digest: DigestAlgorithm, output: HkdfOutput, id: &'a [u8]) -> HkdfRequest<'a> {
    HkdfRequest {
        digest,
        salt: b"public test salt",
        info: b"protocol v1 recipient key",
        output,
        id,
        label: b"derived test key",
    }
}
fn inspect(session: &mut Session<'_>, id: &[u8], output: HkdfOutput) {
    let object = session.resolve(&reference(id, "secret-key")).unwrap();
    let aes = !matches!(output, HkdfOutput::DerivationSecret { .. });
    let attrs = object
        .read_attributes(&[
            AttributeType::Class,
            AttributeType::KeyType,
            AttributeType::Token,
            AttributeType::Private,
            AttributeType::Sensitive,
            AttributeType::Extractable,
            AttributeType::Derive,
            AttributeType::Encrypt,
            AttributeType::Decrypt,
            AttributeType::Sign,
            AttributeType::Verify,
            AttributeType::Wrap,
            AttributeType::Unwrap,
            AttributeType::ValueLen,
        ])
        .unwrap();
    for expected in [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(if aes {
            KeyType::AES
        } else {
            KeyType::GENERIC_SECRET
        }),
        Attribute::Token(true),
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
}
fn public_expected(
    digest: DigestAlgorithm,
    output: HkdfOutput,
    salt: &[u8],
    info: &[u8],
) -> Vec<u8> {
    public_expected_stage(
        digest,
        output,
        salt,
        info,
        pkcs11_runtime::HkdfMode::ExtractAndExpand,
    )
}
fn public_expected_stage(
    digest: DigestAlgorithm,
    output: HkdfOutput,
    salt: &[u8],
    info: &[u8],
    mode: pkcs11_runtime::HkdfMode,
) -> Vec<u8> {
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let hash = match digest {
        DigestAlgorithm::Sha224 => "SHA224",
        DigestAlgorithm::Sha3_224 => "SHA3-224",
        DigestAlgorithm::Sha3_256 => "SHA3-256",
        DigestAlgorithm::Sha3_384 => "SHA3-384",
        DigestAlgorithm::Sha3_512 => "SHA3-512",
        DigestAlgorithm::Sha256 => "SHA256",
        DigestAlgorithm::Sha384 => "SHA384",
        DigestAlgorithm::Sha512 => "SHA512",
    };
    let mut command =
        std::process::Command::new(std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap());
    command.args([
        "kdf",
        "-binary",
        "-keylen",
        &output.length().to_string(),
        "-kdfopt",
        &format!("digest:{hash}"),
        "-kdfopt",
        &format!("hexkey:{}", hex(&vec![0x0B; digest.output_len()])),
    ]);
    command.args([
        "-kdfopt",
        match mode {
            pkcs11_runtime::HkdfMode::ExtractAndExpand => "mode:EXTRACT_AND_EXPAND",
            pkcs11_runtime::HkdfMode::ExtractOnly => "mode:EXTRACT_ONLY",
            pkcs11_runtime::HkdfMode::ExpandOnly => "mode:EXPAND_ONLY",
        },
    ]);
    if !salt.is_empty() {
        command.args(["-kdfopt", &format!("hexsalt:{}", hex(salt))]);
    }
    if !info.is_empty() {
        command.args(["-kdfopt", &format!("hexinfo:{}", hex(info))]);
    }
    let result = command.arg("HKDF").output().unwrap();
    assert!(
        result.status.success(),
        "OpenSSL HKDF failed: {}",
        result.status
    );
    assert_eq!(result.stdout.len(), output.length());
    result.stdout
}
fn base_template(id: &[u8], length: usize) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Derive(true),
        Attribute::Id(id.to_vec()),
        Attribute::Value(vec![0x0B; length]),
    ]
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn typed_hkdf_known_answers_policy_and_ml_kem_agreement() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let path = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let pin = SecretString::from("12345678");
    let so = SecretString::from("87654321");
    let mut module = Module::load(&path).unwrap();
    let slots = module.slots(true).unwrap();
    assert_eq!(slots.len(), 1);
    module.initialize_token(slots[0], &so, "kdf-test").unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::SecurityOfficer(Pin::Value(&so)))
        .unwrap();
    session.initialize_pin(&pin).unwrap();
    session.logout().unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    let outputs = [
        HkdfOutput::Aes128,
        HkdfOutput::Aes192,
        HkdfOutput::Aes256,
        HkdfOutput::DerivationSecret { length: 42 },
    ];
    let mut known_answers = vec![];
    for (index, digest) in [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ]
    .into_iter()
    .enumerate()
    {
        let id = [0xA0, index as u8];
        session
            .create_object(&base_template(&id, digest.output_len()))
            .unwrap();
        let base = reference(&id, "secret-key");
        assert_eq!(
            session
                .hkdf_capabilities(&base, digest)
                .unwrap()
                .input_length,
            digest.output_len()
        );
        for (kind, output) in outputs.into_iter().enumerate() {
            let id = [0xA1, index as u8, kind as u8];
            let request = request(digest, output, &id);
            session.derive_hkdf(&base, &request).unwrap();
            inspect(&mut session, &id, output);
            known_answers.push((
                id.to_vec(),
                output,
                public_expected(digest, output, request.salt, request.info),
            ));
            assert!(matches!(
                session.derive_hkdf(&base, &request),
                Err(Error::InvalidParameters(_))
            ));
        }
    }
    let mut hkdf_base = base_template(b"HKDF base", 32);
    hkdf_base.retain(|attr| !matches!(attr, Attribute::KeyType(_)));
    hkdf_base.push(Attribute::KeyType(KeyType::HKDF));
    session.create_object(&hkdf_base).unwrap();
    let output = request(DigestAlgorithm::Sha256, HkdfOutput::Aes128, b"HKDF output");
    session
        .derive_hkdf(&reference(b"HKDF base", "secret-key"), &output)
        .unwrap();
    known_answers.push((
        output.id.to_vec(),
        output.output,
        public_expected(output.digest, output.output, output.salt, output.info),
    ));
    let base = reference(&[0xA0, 0], "secret-key");
    assert!(matches!(
        session.hkdf_capabilities(&base, DigestAlgorithm::Sha384),
        Err(Error::UnsupportedKeyOperation)
    ));
    let empty_id = [0xA2];
    let mut empty = request(
        DigestAlgorithm::Sha256,
        HkdfOutput::DerivationSecret { length: 8160 },
        &empty_id,
    );
    empty.salt = &[];
    empty.info = &[];
    session.derive_hkdf(&base, &empty).unwrap();
    inspect(&mut session, &empty_id, empty.output);
    known_answers.push((
        empty_id.to_vec(),
        empty.output,
        public_expected(empty.digest, empty.output, &[], &[]),
    ));
    for (index, replacement) in [
        Attribute::Derive(false),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
        Attribute::KeyType(KeyType::AES),
        Attribute::AllowedMechanisms(vec![pkcs11_runtime::MechanismType::AES_KEY_GEN]),
    ]
    .into_iter()
    .enumerate()
    {
        let id = [0xA3, index as u8];
        let mut attrs = base_template(&id, 32);
        attrs.retain(|attr| attr.attribute_type() != replacement.attribute_type());
        attrs.push(replacement);
        session.create_object(&attrs).unwrap();
        assert!(matches!(
            session.derive_hkdf(
                &reference(&id, "secret-key"),
                &request(DigestAlgorithm::Sha256, HkdfOutput::Aes256, b"rejected")
            ),
            Err(Error::UnsupportedKeyOperation)
        ));
        assert!(
            session
                .find_objects(&[Attribute::Id(b"rejected".to_vec())])
                .unwrap()
                .is_empty()
        );
    }
    for (index, digest) in [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ]
    .into_iter()
    .enumerate()
    {
        use pkcs11_runtime::HkdfMode;
        let base = reference(&[0xA0, index as u8], "secret-key");
        let output = HkdfOutput::DerivationSecret {
            length: digest.output_len(),
        };
        let prk_id = [0xE8, 0x48, index as u8, 0];
        let extract = HkdfRequest {
            digest,
            salt: b"extract salt",
            info: &[],
            output,
            id: &prk_id,
            label: b"stage PRK",
        };
        session
            .derive_hkdf_with_mode(&base, &extract, HkdfMode::ExtractOnly)
            .unwrap();
        inspect(&mut session, &prk_id, output);
        known_answers.push((
            prk_id.to_vec(),
            output,
            public_expected_stage(digest, output, extract.salt, &[], HkdfMode::ExtractOnly),
        ));
        for (case, output) in [
            HkdfOutput::Aes128,
            HkdfOutput::Aes192,
            HkdfOutput::Aes256,
            HkdfOutput::DerivationSecret {
                length: 255 * digest.output_len(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            let id = [0xE8, 0x48, index as u8, case as u8 + 1];
            let expand = HkdfRequest {
                digest,
                salt: &[],
                info: b"expand context",
                output,
                id: &id,
                label: b"stage expand",
            };
            session
                .derive_hkdf_with_mode(&base, &expand, HkdfMode::ExpandOnly)
                .unwrap();
            inspect(&mut session, &id, output);
            known_answers.push((
                id.to_vec(),
                output,
                public_expected_stage(digest, output, &[], expand.info, HkdfMode::ExpandOnly),
            ));
        }
    }
    // Salt keys are separate persistent objects, not exported salt bytes.
    for (index, digest) in [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ]
    .into_iter()
    .enumerate()
    {
        use pkcs11_runtime::HkdfMode;
        let base = reference(&[0xA0, index as u8], "secret-key");
        for (case, length) in [1, digest.output_len(), 200, 4096].into_iter().enumerate() {
            let salt_id = [0xF8, 0x53, index as u8, case as u8];
            let salt = vec![0x0C; length];
            let mut attrs = base_template(&salt_id, length);
            for attr in &mut attrs {
                if let Attribute::Value(value) = attr {
                    *value = salt.clone();
                }
                if case == 1 {
                    if let Attribute::KeyType(kind) = attr {
                        *kind = KeyType::HKDF;
                    }
                }
            }
            attrs.push(Attribute::AllowedMechanisms(vec![
                pkcs11_runtime::MechanismType::HKDF_DERIVE,
            ]));
            session.create_object(&attrs).unwrap();
            let salt_key = reference(&salt_id, "secret-key");
            for (stage, mode) in [HkdfMode::ExtractOnly, HkdfMode::ExtractAndExpand]
                .into_iter()
                .enumerate()
            {
                let id = [0xF8, 0x55, index as u8, case as u8, stage as u8];
                let request = HkdfRequest {
                    digest,
                    salt: &[],
                    info: if mode == HkdfMode::ExtractOnly {
                        &[]
                    } else {
                        b"salt key protocol"
                    },
                    output: if mode == HkdfMode::ExtractOnly {
                        HkdfOutput::DerivationSecret {
                            length: digest.output_len(),
                        }
                    } else {
                        HkdfOutput::Aes256
                    },
                    id: &id,
                    label: b"salt key result",
                };
                session
                    .derive_hkdf_with_salt_key(&base, &salt_key, &request, mode)
                    .unwrap();
                inspect(&mut session, &id, request.output);
                known_answers.push((
                    id.to_vec(),
                    request.output,
                    public_expected_stage(digest, request.output, &salt, request.info, mode),
                ));
                assert!(matches!(
                    session.derive_hkdf_with_salt_key(&base, &salt_key, &request, mode),
                    Err(Error::InvalidParameters(_))
                ));
                let fresh = HkdfRequest {
                    id: b"salt-invalid-output",
                    ..request
                };
                for invalid in [
                    HkdfRequest {
                        salt: b"conflict",
                        ..fresh
                    },
                    fresh,
                ] {
                    let mode = if invalid.salt.is_empty() {
                        HkdfMode::ExpandOnly
                    } else {
                        mode
                    };
                    assert!(matches!(
                        session.derive_hkdf_with_salt_key(&base, &salt_key, &invalid, mode),
                        Err(Error::InvalidParameters(_))
                    ));
                    session.info().unwrap();
                }
            }
            if case != 1 {
                session.resolve(&salt_key).unwrap().destroy().unwrap();
            }
        }
    }
    // Selection and policy failures occur before C_DeriveKey and keep the session usable.
    {
        use pkcs11_runtime::{HkdfMode, MechanismType};
        let base = reference(&[0xA0, 0], "secret-key");
        let request = HkdfRequest {
            salt: &[],
            ..request(
                DigestAlgorithm::Sha256,
                HkdfOutput::Aes256,
                b"salt-policy-output",
            )
        };
        for (case, bad) in [
            Attribute::Derive(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::AllowedMechanisms(vec![MechanismType::AES_GCM]),
            Attribute::KeyType(KeyType::AES),
            Attribute::Value(vec![0x0C; 4097]),
        ]
        .into_iter()
        .enumerate()
        {
            let id = [0xF8, 0x54, case as u8];
            let mut attrs = base_template(&id, 32);
            if let Some(attr) = attrs
                .iter_mut()
                .find(|a| a.attribute_type() == bad.attribute_type())
            {
                *attr = bad;
            } else {
                attrs.push(bad);
            }
            session.create_object(&attrs).unwrap();
            let salt_key = reference(&id, "secret-key");
            assert!(matches!(
                session.derive_hkdf_with_salt_key(
                    &base,
                    &salt_key,
                    &request,
                    HkdfMode::ExtractAndExpand
                ),
                Err(Error::UnsupportedKeyOperation)
            ));
            session.info().unwrap();
            session.resolve(&salt_key).unwrap().destroy().unwrap();
        }
        let canonical_salt = reference(&[0xF8, 0x53, 0, 1], "secret-key");
        let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
        assert!(matches!(
            ro.derive_hkdf_with_salt_key(
                &base,
                &canonical_salt,
                &request,
                HkdfMode::ExtractAndExpand
            ),
            Err(Error::ReadWriteRequired)
        ));
        ro.close().unwrap();
        let other_token = ObjectRef::new(
            "pkcs11:token=another-token;id=%01;type=secret-key"
                .parse()
                .unwrap(),
        )
        .unwrap();
        for salt_key in [other_token, reference(b"missing-salt", "secret-key")] {
            assert!(matches!(
                session.derive_hkdf_with_salt_key(
                    &base,
                    &salt_key,
                    &request,
                    HkdfMode::ExtractAndExpand
                ),
                Err(Error::NotFound("object"))
            ));
            session.info().unwrap();
        }
        assert!(matches!(
            session.resolve(&reference(b"salt-policy-output", "secret-key")),
            Err(Error::NotFound("object"))
        ));
    }
    for (index, parameter) in [
        MlKemParameterSet::MlKem512,
        MlKemParameterSet::MlKem768,
        MlKemParameterSet::MlKem1024,
    ]
    .into_iter()
    .enumerate()
    {
        let id = [0xB0, index as u8];
        session
            .generate_ml_kem_key_pair(parameter, &id, b"KEM recipient")
            .unwrap();
        let public =
            PublicKeyRef::new(reference(&id, "public").uri().to_string().parse().unwrap()).unwrap();
        let private =
            PrivateKeyRef::new(reference(&id, "private").uri().to_string().parse().unwrap())
                .unwrap();
        let ciphertext = session
            .encapsulate_ml_kem(
                &public,
                &MlKemRequest {
                    parameter_set: parameter,
                    id: &[0xB1, index as u8, 0],
                    label: b"sender",
                },
            )
            .unwrap();
        session
            .decapsulate_ml_kem(
                &private,
                &MlKemRequest {
                    parameter_set: parameter,
                    id: &[0xB1, index as u8, 1],
                    label: b"receiver",
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
                    parameter_set: parameter,
                    id: &[0xB1, index as u8, 2],
                    label: b"implicit rejection",
                },
                &altered,
            )
            .unwrap();
        for direction in 0..=3 {
            let id = [0xB2, index as u8, direction];
            let mut derive = request(DigestAlgorithm::Sha256, HkdfOutput::Aes256, &id);
            if direction == 3 {
                derive.info = b"different protocol context";
            }
            session
                .derive_hkdf(
                    &reference(
                        &[
                            0xB1,
                            index as u8,
                            if direction == 3 { 0 } else { direction },
                        ],
                        "secret-key",
                    ),
                    &derive,
                )
                .unwrap();
            inspect(&mut session, &id, HkdfOutput::Aes256);
        }
    }
    // A public base remains selectable after logout; provider refusal invalidates the session.
    let mut public_base = base_template(b"public base", 32);
    public_base.retain(|attr| !matches!(attr, Attribute::Private(_)));
    public_base.push(Attribute::Private(false));
    session.create_object(&public_base).unwrap();
    session.logout().unwrap();
    assert!(matches!(
        session.derive_hkdf(
            &reference(b"public base", "secret-key"),
            &request(
                DigestAlgorithm::Sha256,
                HkdfOutput::Aes128,
                b"unauthenticated output"
            )
        ),
        Err(Error::Backend {
            operation: "derive HKDF key",
            ..
        })
    ));
    assert!(matches!(
        session.hkdf_capabilities(&base, DigestAlgorithm::Sha256),
        Err(Error::Closed)
    ));
    session.close().unwrap();
    let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
    assert!(matches!(
        ro.derive_hkdf(
            &base,
            &request(DigestAlgorithm::Sha256, HkdfOutput::Aes256, b"read-only")
        ),
        Err(Error::ReadWriteRequired)
    ));
    ro.close().unwrap();
    module.finalize().unwrap();

    // A separate lifecycle checks entire generic secrets and AES results without exporting them.
    let module = Pkcs11::new(&path).unwrap();
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = module.get_slots_with_initialized_token().unwrap()[0];
    let session = module.open_rw_session(slot).unwrap();
    session.login(UserType::User, Some(&pin)).unwrap();
    let find = |id: &[u8]| {
        let objects = session
            .find_objects(&[
                Attribute::Token(true),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::Id(id.to_vec()),
            ])
            .unwrap();
        assert_eq!(objects.len(), 1);
        objects[0]
    };
    let challenge = [0xA5; 32];
    for (id, output, expected) in known_answers {
        let derived = find(&id);
        let generic = matches!(output, HkdfOutput::DerivationSecret { .. });
        if generic {
            session
                .update_attributes(derived, &[Attribute::Sign(true)])
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
                Attribute::Value(expected),
                Attribute::Sign(generic),
                Attribute::Encrypt(!generic),
            ])
            .unwrap();
        if generic {
            assert_eq!(
                session
                    .sign(&Mechanism::Sha256Hmac, derived, &challenge)
                    .unwrap(),
                session
                    .sign(&Mechanism::Sha256Hmac, imported, &challenge)
                    .unwrap()
            );
            session
                .update_attributes(derived, &[Attribute::Sign(false)])
                .unwrap();
        } else {
            assert_eq!(
                session
                    .encrypt(&Mechanism::AesEcb, derived, &challenge)
                    .unwrap(),
                session
                    .encrypt(&Mechanism::AesEcb, imported, &challenge)
                    .unwrap()
            );
        }
        session.destroy_object(imported).unwrap();
        if id.starts_with(&[0xF8, 0x55]) {
            session.destroy_object(derived).unwrap();
        }
    }
    for index in 0..3 {
        let encrypt = |direction| {
            session
                .encrypt(
                    &Mechanism::AesEcb,
                    find(&[0xB2, index, direction]),
                    &challenge,
                )
                .unwrap()
        };
        assert_eq!(encrypt(0), encrypt(1));
        assert_ne!(encrypt(0), encrypt(2));
        assert_ne!(encrypt(0), encrypt(3));
    }
    session.close().unwrap();
    module.finalize().unwrap();
}
