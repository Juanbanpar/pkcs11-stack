// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native SP800-108 modes compared with OpenSSL KBKDF and an independent HMAC construction.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::KeyType,
    session::UserType,
};
use pkcs11_runtime::{
    Attribute, AttributeType, Authentication, DigestAlgorithm, Error, KbkdfMode, KbkdfOutput,
    KbkdfPrf, KbkdfPrfRequest, KbkdfRequest, MechanismType, Module, ObjectClass, ObjectRef, Pin,
    SessionMode,
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
    let mut attrs = vec![
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
        Attribute::AllowedMechanisms(vec![
            MechanismType::SP800_108_COUNTER_KDF,
            MechanismType::SP800_108_FEEDBACK_KDF,
            MechanismType::SP800_108_DOUBLE_PIPELINE_KDF,
        ]),
        Attribute::Id(id.to_vec()),
        Attribute::Value(vec![0x0B; length]),
    ];
    // NSS does not persist CKA_ALLOWED_MECHANISMS on imported secret objects.
    // Native fixtures and the Kryoptic lane cover explicit mechanism restrictions.
    if std::env::var("PKCS11_TEST_NSS_ISOLATED").as_deref() == Ok("1") {
        attrs.retain(|a| a.attribute_type() != AttributeType::AllowedMechanisms);
    }
    attrs
}
fn expected(
    mode: KbkdfMode,
    iv: &[u8],
    digest: DigestAlgorithm,
    key_length: usize,
    output: KbkdfOutput,
    label: &[u8],
    context: &[u8],
) -> Vec<u8> {
    if mode == KbkdfMode::DoublePipeline {
        return double_pipeline_expected(digest, key_length, output.length(), label, context);
    }
    let hex = |v: &[u8]| v.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut cmd = std::process::Command::new(std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap());
    cmd.args([
        "kdf",
        "-binary",
        "-keylen",
        &output.length().to_string(),
        "-kdfopt",
        if mode == KbkdfMode::Counter {
            "mode:COUNTER"
        } else {
            "mode:FEEDBACK"
        },
        "-kdfopt",
        "mac:HMAC",
        "-kdfopt",
        match digest {
            DigestAlgorithm::Sha224 => "digest:SHA224",
            DigestAlgorithm::Sha3_224 => "digest:SHA3-224",
            DigestAlgorithm::Sha3_256 => "digest:SHA3-256",
            DigestAlgorithm::Sha3_384 => "digest:SHA3-384",
            DigestAlgorithm::Sha3_512 => "digest:SHA3-512",
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
    if !iv.is_empty() {
        cmd.args(["-kdfopt", &format!("hexseed:{}", hex(iv))]);
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
fn kbkdf_modes_openssl_outputs_key_types_permissions_and_bounds() {
    for mode in [KbkdfMode::Counter, KbkdfMode::Feedback] {
        check_mode(mode);
    }
}
fn check_mode(mode: KbkdfMode) {
    let canonical_id = match mode {
        KbkdfMode::Counter => 0x82,
        KbkdfMode::Feedback => 0x8a,
        KbkdfMode::DoublePipeline => 0x8b,
    };
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
        token.mechanisms().unwrap().contains(&match mode {
            KbkdfMode::Counter => MechanismType::SP800_108_COUNTER_KDF,
            KbkdfMode::Feedback => MechanismType::SP800_108_FEEDBACK_KDF,
            KbkdfMode::DoublePipeline => MechanismType::SP800_108_DOUBLE_PIPELINE_KDF,
        }),
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
            // NSS omits CKA_VALUE_LEN on typed HMAC keys. Do not infer their
            // length from the hash name: HMAC key lengths are variable.
            if mode == KbkdfMode::DoublePipeline && typed {
                assert!(matches!(
                    session.kbkdf_capabilities_with_mode(&key, mode),
                    Err(Error::MissingMetadata(_))
                ));
                session.info().unwrap();
                session.resolve(&key).unwrap().destroy().unwrap();
                continue;
            }
            let caps = session.kbkdf_capabilities_with_mode(&key, mode).unwrap();
            assert_eq!(caps.input_length, key_length);
            for candidate in [
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
            ] {
                assert_eq!(caps.supports(candidate), !typed || candidate == digest);
                if !caps.supports(candidate) {
                    assert!(matches!(
                        session.derive_kbkdf_with_mode(
                            &key,
                            &KbkdfRequest {
                                digest: candidate,
                                kdf_label: b"label",
                                context: b"ctx",
                                output: KbkdfOutput::Aes256,
                                id: b"wrong-prf",
                                label: b"wrong"
                            },
                            mode,
                            &[]
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
                let iv_storage = if mode == KbkdfMode::Feedback && case % 2 == 0 {
                    vec![0xA5; digest.output_len()]
                } else {
                    Vec::new()
                };
                let iv = iv_storage.as_slice();
                let request = KbkdfRequest {
                    digest,
                    kdf_label: label,
                    context,
                    output,
                    id: &id,
                    label: b"counter output",
                };
                session
                    .derive_kbkdf_with_mode(&key, &request, mode, iv)
                    .unwrap();
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
                    expected(mode, iv, digest, key_length, output, label, context),
                ));
                assert!(matches!(
                    session.derive_kbkdf_with_mode(&key, &request, mode, iv),
                    Err(Error::InvalidParameters(_))
                ));
            }
            session.resolve(&key).unwrap().destroy().unwrap();
        }
        let id = [0xFA, canonical_id, index as u8];
        let iv = if mode == KbkdfMode::Feedback {
            vec![0xA5; digest.output_len()]
        } else {
            Vec::new()
        };
        let request = KbkdfRequest {
            digest,
            kdf_label: b"application",
            context: b"v1 context",
            output: KbkdfOutput::Aes256,
            id: &id,
            label: b"counter canonical AES",
        };
        session
            .derive_kbkdf_with_mode(&reference(&[0xA0, index as u8]), &request, mode, &iv)
            .unwrap();
        proofs.push((
            id.to_vec(),
            request.output,
            expected(
                mode,
                &iv,
                digest,
                digest.output_len(),
                request.output,
                request.kdf_label,
                request.context,
            ),
        ));
    }
    // Kryoptic preserves the hostile templates below. NSS normalizes persistent
    // templates and omits some attributes; independent ABI fixtures cover the
    // same policy rejections for DoublePipeline.
    if mode != KbkdfMode::DoublePipeline {
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
                session.kbkdf_capabilities_with_mode(&reference(&id), mode),
                Err(Error::UnsupportedKeyOperation)
            ));
            let result = session.derive_kbkdf_with_mode(
                &reference(&id),
                &KbkdfRequest {
                    digest: DigestAlgorithm::Sha256,
                    kdf_label: b"label",
                    context: b"ctx",
                    output: KbkdfOutput::Aes256,
                    id: b"policy-output",
                    label: b"policy",
                },
                mode,
                &[],
            );
            assert!(matches!(result, Err(Error::UnsupportedKeyOperation)));
            session.info().unwrap();
            session.resolve(&reference(&id)).unwrap().destroy().unwrap();
        }
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
        session
            .derive_kbkdf_with_mode(&reference(&id), &request, mode, &[])
            .unwrap();
        proofs.push((
            request.id.to_vec(),
            request.output,
            expected(
                mode,
                &[],
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
        ro.derive_kbkdf_with_mode(&reference(&[0xA0, 0]), &request, mode, &[]),
        Err(Error::ReadWriteRequired)
    ));
    ro.close().unwrap();
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
    prove_outputs(&path, &pin, proofs, canonical_id);
}
fn prove_outputs(
    path: &std::ffi::OsStr,
    pin: &SecretString,
    proofs: Vec<(Vec<u8>, KbkdfOutput, Vec<u8>)>,
    canonical_id: u8,
) {
    let raw = Pkcs11::new(path).unwrap();
    raw.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = raw
        .get_slots_with_initialized_token()
        .unwrap()
        .into_iter()
        .find(|slot| raw.get_token_info(*slot).unwrap().label() == "kdf-test")
        .unwrap();
    let session = raw.open_rw_session(slot).unwrap();
    session.login(UserType::User, Some(pin)).unwrap();
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
        if !id.starts_with(&[0xFA, canonical_id]) {
            session.destroy_object(key).unwrap();
        }
    }
    session.close().unwrap();
    raw.finalize().unwrap();
}

// SP800-108 section 5.3: the construction is independent of the provider's
// KBKDF implementation. OpenSSL is used only as an HMAC primitive.
fn double_pipeline_expected(
    digest: DigestAlgorithm,
    key_length: usize,
    length: usize,
    label: &[u8],
    context: &[u8],
) -> Vec<u8> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let prf = |message: &[u8]| {
        let mut child = Command::new(std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap())
            .args([
                "dgst",
                match digest {
                    DigestAlgorithm::Sha256 => "-sha256",
                    DigestAlgorithm::Sha384 => "-sha384",
                    DigestAlgorithm::Sha512 => "-sha512",
                    _ => unreachable!(),
                },
                "-mac",
                "HMAC",
                "-macopt",
                &format!("hexkey:{}", "0b".repeat(key_length)),
                "-binary",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(message).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "OpenSSL HMAC: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout.len(), digest.output_len());
        out.stdout
    };
    let mut fixed = label.to_vec();
    fixed.push(0);
    fixed.extend(context);
    fixed.extend(u32::try_from(length * 8).unwrap().to_be_bytes());
    let mut a = fixed.clone();
    let mut result = Vec::new();
    for counter in 1u32.. {
        a = prf(&a);
        let mut block = a.clone();
        block.extend(counter.to_be_bytes());
        block.extend(&fixed);
        result.extend(prf(&block));
        if result.len() >= length {
            result.truncate(length);
            return result;
        }
    }
    unreachable!()
}
#[test]
#[ignore = "requires tools/test-nss.sh disposable NSS store"]
fn double_pipeline_nss_outputs_key_types_permissions_and_bounds() {
    assert_eq!(
        std::env::var("PKCS11_TEST_NSS_ISOLATED").as_deref(),
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
    for (index, length) in [32, 48, 64].into_iter().enumerate() {
        session
            .create_object(&base(&[0xa0, index as u8], KeyType::GENERIC_SECRET, length))
            .unwrap();
    }
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
    check_mode(KbkdfMode::DoublePipeline);
}

// CMAC references use OpenSSL KBKDF for Counter/Feedback. Double Pipeline is
// constructed independently with OpenSSL used only as a full-block CMAC primitive.
fn cmac_expected(
    mode: KbkdfMode,
    iv: &[u8],
    key_length: usize,
    length: usize,
    label: &[u8],
    context: &[u8],
) -> Vec<u8> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let hex = |v: &[u8]| v.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let cipher = format!("AES-{}-CBC", key_length * 8);
    let key = "0b".repeat(key_length);
    let binary = std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap();
    if mode != KbkdfMode::DoublePipeline {
        let mut command = Command::new(&binary);
        command.args([
            "kdf",
            "-binary",
            "-keylen",
            &length.to_string(),
            "-kdfopt",
            if mode == KbkdfMode::Counter {
                "mode:COUNTER"
            } else {
                "mode:FEEDBACK"
            },
            "-kdfopt",
            "mac:CMAC",
            "-kdfopt",
            &format!("cipher:{cipher}"),
            "-kdfopt",
            &format!("hexkey:{key}"),
            "-kdfopt",
            "use-l:1",
            "-kdfopt",
            "use-separator:1",
        ]);
        for (name, bytes) in [("hexsalt", label), ("hexinfo", context), ("hexseed", iv)] {
            if !bytes.is_empty() {
                command.args(["-kdfopt", &format!("{name}:{}", hex(bytes))]);
            }
        }
        let out = command.arg("KBKDF").output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout.len(), length);
        return out.stdout;
    }
    let cmac = |bytes: &[u8]| {
        let mut child = Command::new(&binary)
            .args([
                "mac",
                "-binary",
                "-macopt",
                &format!("cipher:{cipher}"),
                "-macopt",
                &format!("hexkey:{key}"),
                "CMAC",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout.len(), 16);
        out.stdout
    };
    let mut fixed = label.to_vec();
    fixed.push(0);
    fixed.extend(context);
    fixed.extend(u32::try_from(length * 8).unwrap().to_be_bytes());
    let mut a = fixed.clone();
    let mut result = vec![];
    for i in 1u32.. {
        a = cmac(&a);
        let mut block = a.clone();
        block.extend(i.to_be_bytes());
        block.extend(&fixed);
        result.extend(cmac(&block));
        if result.len() >= length {
            result.truncate(length);
            return result;
        }
    }
    unreachable!()
}
#[test]
#[ignore = "requires an isolated NSS or Kryoptic store through the provider runners"]
fn kbkdf_aes_cmac_modes_outputs_permissions_and_independent_references() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let nss = std::env::var("PKCS11_TEST_NSS_ISOLATED").as_deref() == Ok("1");
    let modes = if nss {
        KbkdfMode::ALL.as_slice()
    } else {
        &KbkdfMode::ALL[..2]
    };
    let path = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let pin = SecretString::from("12345678");
    // Retained bases and canonical outputs are used by the client and CLI suites.
    {
        let module = Module::load(&path).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
        session
            .authenticate(Authentication::User(Pin::Value(&pin)))
            .unwrap();
        for (index, length) in [16, 24, 32].into_iter().enumerate() {
            session
                .create_object(&base(&[0xFA, 0x93, index as u8], KeyType::AES, length))
                .unwrap();
        }
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
    for (mode_index, &mode) in modes.iter().enumerate() {
        let canonical = 0x90 + mode_index as u8;
        let module = Module::load(&path).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
        session
            .authenticate(Authentication::User(Pin::Value(&pin)))
            .unwrap();
        let mut proofs = vec![];
        for (index, length) in [16, 24, 32].into_iter().enumerate() {
            let key = reference(&[0xFA, 0x93, index as u8]);
            let caps = session
                .kbkdf_prf_capabilities(&key, KbkdfPrf::AesCmac, mode)
                .unwrap();
            assert_eq!(caps.input_length, length);
            assert!(matches!(
                session.kbkdf_capabilities_with_mode(&key, mode),
                Err(Error::UnsupportedKeyOperation)
            ));
            if !nss {
                assert!(matches!(
                    session.kbkdf_prf_capabilities(
                        &key,
                        KbkdfPrf::AesCmac,
                        KbkdfMode::DoublePipeline
                    ),
                    Err(Error::UnsupportedKeyOperation)
                ));
            }
            for (case, output) in [
                KbkdfOutput::Aes128,
                KbkdfOutput::Aes192,
                KbkdfOutput::Aes256,
                KbkdfOutput::DerivationSecret { length: 1 },
                KbkdfOutput::DerivationSecret { length: 17 },
                KbkdfOutput::DerivationSecret { length: 128 },
                KbkdfOutput::DerivationSecret { length: 4096 },
            ]
            .into_iter()
            .enumerate()
            {
                let id = [0xFA, 0x94, mode_index as u8, index as u8, case as u8];
                let long = [0xA5; 4096];
                let (label, context) = match case % 4 {
                    0 => (&[][..], &[][..]),
                    1 => (b"label\0binary".as_slice(), b"\xFFctx\0".as_slice()),
                    2 => (long.as_slice(), long.as_slice()),
                    _ => (b"label".as_slice(), b"ctx".as_slice()),
                };
                let iv = if mode == KbkdfMode::Feedback && case % 2 == 0 {
                    vec![0xA5; 16]
                } else {
                    vec![]
                };
                let request = KbkdfPrfRequest {
                    prf: KbkdfPrf::AesCmac,
                    kdf_label: label,
                    context,
                    output,
                    id: &id,
                    label: b"CMAC KDF output",
                };
                session.derive_kbkdf_prf(&key, &request, mode, &iv).unwrap();
                let object = session.resolve(&reference(&id)).unwrap();
                let attrs = object
                    .read_attributes(&[
                        AttributeType::Sensitive,
                        AttributeType::Extractable,
                        AttributeType::Derive,
                        AttributeType::Sign,
                        AttributeType::Verify,
                        AttributeType::Encrypt,
                        AttributeType::Decrypt,
                        AttributeType::Wrap,
                        AttributeType::Unwrap,
                        AttributeType::Private,
                        AttributeType::ValueLen,
                    ])
                    .unwrap();
                let aes = !matches!(output, KbkdfOutput::DerivationSecret { .. });
                for expected in [
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Private(true),
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
                    [pkcs11_runtime::AttributeInfo::Sensitive]
                ));
                proofs.push((
                    id.to_vec(),
                    output,
                    cmac_expected(mode, &iv, length, output.length(), label, context),
                ));
                assert!(matches!(
                    session.derive_kbkdf_prf(&key, &request, mode, &iv),
                    Err(Error::InvalidParameters(_))
                ));
            }
            let id = [0xFA, canonical, index as u8];
            let iv = if mode == KbkdfMode::Feedback {
                vec![0xA5; 16]
            } else {
                vec![]
            };
            let request = KbkdfPrfRequest {
                prf: KbkdfPrf::AesCmac,
                kdf_label: b"application",
                context: b"v1 context",
                output: KbkdfOutput::Aes256,
                id: &id,
                label: b"CMAC KDF reference",
            };
            session.derive_kbkdf_prf(&key, &request, mode, &iv).unwrap();
            proofs.push((
                id.to_vec(),
                request.output,
                cmac_expected(mode, &iv, length, 32, request.kdf_label, request.context),
            ));
            let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
            assert!(matches!(
                ro.derive_kbkdf_prf(&key, &request, mode, &iv),
                Err(Error::ReadWriteRequired)
            ));
            ro.close().unwrap();
        }
        // A generic secret of a valid AES length must not be reinterpreted as AES.
        let id = [0xFA, 0x97, mode_index as u8];
        session
            .create_object(&base(&id, KeyType::GENERIC_SECRET, 32))
            .unwrap();
        assert!(matches!(
            session.kbkdf_prf_capabilities(&reference(&id), KbkdfPrf::AesCmac, mode),
            Err(Error::UnsupportedKeyOperation)
        ));
        session.info().unwrap();
        session.resolve(&reference(&id)).unwrap().destroy().unwrap();
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
        prove_outputs(&path, &pin, proofs, canonical);
    }
}

#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn kbkdf_hmac_profiles_openssl_agreement_and_protected_outputs() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let path = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let pin = SecretString::from("12345678");
    let profiles = [
        (
            KbkdfPrf::HmacSha224,
            DigestAlgorithm::Sha224,
            KeyType::SHA224_HMAC,
        ),
        (
            KbkdfPrf::HmacSha3_224,
            DigestAlgorithm::Sha3_224,
            KeyType::SHA3_224_HMAC,
        ),
        (
            KbkdfPrf::HmacSha3_256,
            DigestAlgorithm::Sha3_256,
            KeyType::SHA3_256_HMAC,
        ),
        (
            KbkdfPrf::HmacSha3_384,
            DigestAlgorithm::Sha3_384,
            KeyType::SHA3_384_HMAC,
        ),
        (
            KbkdfPrf::HmacSha3_512,
            DigestAlgorithm::Sha3_512,
            KeyType::SHA3_512_HMAC,
        ),
    ];
    {
        let module = Module::load(&path).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
        session
            .authenticate(Authentication::User(Pin::Value(&pin)))
            .unwrap();
        for (index, (prf, _, typed)) in profiles.iter().enumerate() {
            for (is_typed, kind) in [(false, KeyType::GENERIC_SECRET), (true, *typed)] {
                session
                    .create_object(&base(
                        &[0xFA, 0xA7, index as u8, u8::from(is_typed)],
                        kind,
                        if is_typed { prf.output_len() } else { 31 },
                    ))
                    .unwrap_or_else(|e| panic!("base profile {index}, typed={is_typed}: {e:?}"));
            }
        }
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
    for (mode_index, mode) in [KbkdfMode::Counter, KbkdfMode::Feedback]
        .into_iter()
        .enumerate()
    {
        let canonical = 0xA8 + mode_index as u8;
        let module = Module::load(&path).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
        session
            .authenticate(Authentication::User(Pin::Value(&pin)))
            .unwrap();
        let mut proofs = vec![];
        for (index, (prf, digest, _)) in profiles.into_iter().enumerate() {
            for typed in [false, true] {
                let key = reference(&[0xFA, 0xA7, index as u8, u8::from(typed)]);
                let caps = session.kbkdf_prf_capabilities(&key, prf, mode).unwrap();
                let key_length = if typed { prf.output_len() } else { 31 };
                assert_eq!(caps.input_length, key_length);
                assert_eq!(caps.prf, prf);
                assert!(matches!(
                    session.kbkdf_prf_capabilities(&key, prf, KbkdfMode::DoublePipeline),
                    Err(Error::UnsupportedKeyOperation)
                ));
                if typed {
                    for (other, ..) in profiles {
                        if other != prf {
                            assert!(matches!(
                                session.kbkdf_prf_capabilities(&key, other, mode),
                                Err(Error::UnsupportedKeyOperation)
                            ));
                        }
                    }
                }
                for (case, output) in [
                    KbkdfOutput::Aes128,
                    KbkdfOutput::Aes192,
                    KbkdfOutput::Aes256,
                    KbkdfOutput::DerivationSecret { length: 1 },
                    KbkdfOutput::DerivationSecret {
                        length: prf.output_len() + 1,
                    },
                    KbkdfOutput::DerivationSecret { length: 4096 },
                ]
                .into_iter()
                .enumerate()
                {
                    let id = [
                        0xFA,
                        0xAA,
                        mode_index as u8,
                        index as u8,
                        u8::from(typed),
                        case as u8,
                    ];
                    let long = [0xA5; 4096];
                    let (label, context) = match case % 3 {
                        0 => (&[][..], &[][..]),
                        1 => (b"label\0binary".as_slice(), b"\xFFcontext\0".as_slice()),
                        _ => (long.as_slice(), long.as_slice()),
                    };
                    let iv = if mode == KbkdfMode::Feedback && case % 2 == 0 {
                        vec![0xA5; prf.output_len()]
                    } else {
                        vec![]
                    };
                    let request = KbkdfPrfRequest {
                        prf,
                        kdf_label: label,
                        context,
                        output,
                        id: &id,
                        label: b"HMAC KDF output",
                    };
                    session.derive_kbkdf_prf(&key, &request, mode, &iv).unwrap();
                    assert!(matches!(
                        session.derive_kbkdf_prf(&key, &request, mode, &iv),
                        Err(Error::InvalidParameters(_))
                    ));
                    let object = session.resolve(&reference(&id)).unwrap();
                    let attrs = object
                        .read_attributes(&[
                            AttributeType::Sensitive,
                            AttributeType::Extractable,
                            AttributeType::Private,
                            AttributeType::Sign,
                            AttributeType::Verify,
                            AttributeType::Derive,
                            AttributeType::Encrypt,
                            AttributeType::Decrypt,
                            AttributeType::Wrap,
                            AttributeType::Unwrap,
                            AttributeType::ValueLen,
                        ])
                        .unwrap();
                    let generic = matches!(output, KbkdfOutput::DerivationSecret { .. });
                    for expected in [
                        Attribute::Sensitive(true),
                        Attribute::Extractable(false),
                        Attribute::Private(true),
                        Attribute::Sign(false),
                        Attribute::Verify(false),
                        Attribute::Derive(generic),
                        Attribute::Encrypt(!generic),
                        Attribute::Decrypt(!generic),
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
                        [pkcs11_runtime::AttributeInfo::Sensitive]
                    ));
                    proofs.push((
                        id.to_vec(),
                        output,
                        expected(mode, &iv, digest, key_length, output, label, context),
                    ));
                }
            }
            let id = [0xFA, canonical, index as u8];
            let key = reference(&[0xFA, 0xA7, index as u8, 1]);
            let iv = if mode == KbkdfMode::Feedback {
                vec![0xA5; prf.output_len()]
            } else {
                vec![]
            };
            let request = KbkdfPrfRequest {
                prf,
                kdf_label: b"application",
                context: b"v1 context",
                output: KbkdfOutput::Aes256,
                id: &id,
                label: b"HMAC KDF reference",
            };
            session.derive_kbkdf_prf(&key, &request, mode, &iv).unwrap();
            proofs.push((
                id.to_vec(),
                request.output,
                expected(
                    mode,
                    &iv,
                    digest,
                    prf.output_len(),
                    request.output,
                    request.kdf_label,
                    request.context,
                ),
            ));
        }
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
        prove_outputs(&path, &pin, proofs, canonical);
    }
}
