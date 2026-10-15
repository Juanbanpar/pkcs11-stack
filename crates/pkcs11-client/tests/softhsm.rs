// SPDX-License-Identifier: MIT OR Apache-2.0
//! Run only through tools/test-softhsm.sh with its disposable token store.
use pkcs11_client::*;
use pkcs11_runtime::Error as RuntimeError;
use secrecy::SecretString;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{num::NonZeroUsize, path::PathBuf, process::Command};

fn uri(label: &str, class: &str) -> Pkcs11Uri {
    format!("pkcs11:token=client-test;object={label};type={class}")
        .parse()
        .unwrap()
}
fn auth(pin: &SecretString) -> Authentication<'_> {
    Authentication::User(Pin::Value(pin))
}
fn connect(module: &Module, hashing: HashingPolicy) -> Client<'_> {
    Client::connect(
        module,
        &"pkcs11:token=client-test".parse().unwrap(),
        NonZeroUsize::new(2).unwrap(),
        SigningPolicy {
            hashing,
            ..SigningPolicy::default()
        },
    )
    .unwrap()
}
fn command(program: &str, args: &[&str]) {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn key_tool(module: &str, args: &[&str]) {
    let mut all = vec![
        "--module",
        module,
        "--token-label",
        "client-test",
        "--login",
        "--pin",
        "12345678",
    ];
    all.extend_from_slice(args);
    command("pkcs11-tool", &all);
}

#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn application_workflows() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let path = std::env::var("PKCS11_TEST_MODULE").unwrap();
    let scratch = PathBuf::from(std::env::var("PKCS11_CLIENT_TEST_DIR").unwrap());
    let pin = SecretString::from("12345678");
    let bad_pin = SecretString::from("incorrect");
    let module = Module::load(&path).unwrap();
    for selector in [
        "pkcs11:token=client-test;library-description=wrong",
        "pkcs11:token=client-test;slot-id=18446744073709551614",
        "pkcs11:token=client-test?module-path=/wrong.so",
    ] {
        assert!(matches!(
            module.resolve_token_uri(&selector.parse().unwrap()),
            Err(RuntimeError::NotFound("token"))
        ));
    }
    assert!(matches!(
        module.resolve_token_uri(&"pkcs11:token=runtime-test".parse().unwrap()),
        Err(RuntimeError::Ambiguous { .. })
    ));
    let token = module
        .resolve_token_uri(&"pkcs11:token=client-test".parse().unwrap())
        .unwrap();
    let constrained: Pkcs11Uri = format!("pkcs11:token=client-test;slot-id={}", token.slot().id())
        .parse()
        .unwrap();
    module.resolve_token_uri(&constrained).unwrap();
    let client = connect(&module, HashingPolicy::SoftwareOnly);
    // Public certificates do not require login; private lookup is explicit.
    client
        .certificate(uri("rsa", "cert"), Authentication::None)
        .unwrap();
    assert!(matches!(
        client.private_key(uri("rsa", "private"), Authentication::None),
        Err(Error::Runtime(RuntimeError::NotFound("object")))
    ));
    assert!(
        client
            .private_key(uri("rsa", "private"), auth(&bad_pin))
            .is_err()
    );
    let rsa_key = client
        .private_key(uri("rsa", "private"), auth(&pin))
        .unwrap();
    client.public_key(uri("rsa", "public"), auth(&pin)).unwrap();
    client.public_metadata(&rsa_key, auth(&pin)).unwrap();
    let values = client
        .attributes(
            rsa_key.as_object_ref(),
            &[AttributeType::Extractable],
            auth(&pin),
        )
        .unwrap();
    assert_eq!(values.expose_values(), &[Attribute::Extractable(false)]);
    assert!(matches!(
        client.private_key(uri("missing", "private"), auth(&pin)),
        Err(Error::Runtime(RuntimeError::NotFound("object")))
    ));
    assert!(matches!(
        client.private_key(uri("duplicate", "private"), auth(&pin)),
        Err(Error::Runtime(RuntimeError::Ambiguous { .. }))
    ));
    assert!(matches!(
        client.certificate(uri("duplicate", "cert"), auth(&pin)),
        Err(Error::Runtime(RuntimeError::Ambiguous { .. }))
    ));
    // Same key type/size is insufficient: this must actually fail signature verification.
    let wrong = client
        .certificate(uri("wrong", "cert"), auth(&pin))
        .unwrap();
    assert!(matches!(
        client.bind_identity(rsa_key, wrong, auth(&pin), None),
        Err(Error::KeyCertificateMismatch)
    ));
    let mut identities = Vec::new();
    for label in ["rsa", "p256", "p384", "p521"] {
        let key = client
            .private_key(uri(label, "private"), auth(&pin))
            .unwrap();
        let attributes = client
            .attributes(
                key.as_object_ref(),
                &[AttributeType::Extractable, AttributeType::Sensitive],
                auth(&pin),
            )
            .unwrap();
        assert!(
            attributes
                .expose_values()
                .contains(&Attribute::Extractable(false))
        );
        assert!(
            attributes
                .expose_values()
                .contains(&Attribute::Sensitive(true))
        );
        let cert = client.certificate(uri(label, "cert"), auth(&pin)).unwrap();
        identities.push(client.bind_identity(key, cert, auth(&pin), None).unwrap());
    }
    let message = b"application signing round trip";
    for identity in &identities {
        let rsa = matches!(identity.certificate().key_kind(), KeyKind::Rsa { .. });
        let algorithms: &[SignatureAlgorithm] = if rsa {
            &[SignatureAlgorithm::RsaPkcs1, SignatureAlgorithm::RsaPss]
        } else {
            &[SignatureAlgorithm::Ecdsa]
        };
        for digest in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let hash = match digest {
                DigestAlgorithm::Sha256 => Sha256::digest(message).to_vec(),
                DigestAlgorithm::Sha384 => Sha384::digest(message).to_vec(),
                DigestAlgorithm::Sha512 => Sha512::digest(message).to_vec(),
            };
            for &algorithm in algorithms {
                for input in [SignInput::Message(message), SignInput::Digest(&hash)] {
                    let request = SignRequest {
                        algorithm,
                        digest,
                        input,
                        pss: (algorithm == SignatureAlgorithm::RsaPss).then_some(PssParameters {
                            mgf_digest: digest,
                            salt_len: 20,
                        }),
                    };
                    client.plan(identity.key(), &request, auth(&pin)).unwrap();
                    let signature = client
                        .sign_identity(identity, &request, auth(&pin), None)
                        .unwrap();
                    assert!(!signature.is_empty());
                }
            }
        }
    }
    let request = SignRequest {
        algorithm: SignatureAlgorithm::RsaPkcs1,
        digest: DigestAlgorithm::Sha256,
        input: SignInput::Message(message),
        pss: None,
    };
    let signature = client
        .sign(identities[0].key(), &request, auth(&pin), None)
        .unwrap();
    std::fs::write(scratch.join("message"), message).unwrap();
    std::fs::write(scratch.join("signature"), signature).unwrap();
    command(
        "openssl",
        &[
            "dgst",
            "-sha256",
            "-verify",
            scratch.join("01-public.pem").to_str().unwrap(),
            "-signature",
            scratch.join("signature").to_str().unwrap(),
            scratch.join("message").to_str().unwrap(),
        ],
    );
    // Unsupported binding verification is rejected even with an exhausted pool.
    let first = client.pool().try_acquire(auth(&pin)).unwrap();
    let second = client.pool().try_acquire(auth(&pin)).unwrap();
    assert!(matches!(
        client.sign_identity(&identities[0], &request, auth(&pin), None),
        Err(Error::Runtime(RuntimeError::PoolExhausted))
    ));
    let unsupported = SignRequest {
        algorithm: SignatureAlgorithm::RsaPss,
        pss: Some(PssParameters {
            mgf_digest: DigestAlgorithm::Sha384,
            salt_len: 20,
        }),
        ..request
    };
    assert!(matches!(
        client.sign_identity(&identities[0], &unsupported, auth(&pin), None),
        Err(Error::UnsupportedVerification)
    ));
    drop(first);
    drop(second);
    let mut discarded = client.pool().try_acquire(auth(&pin)).unwrap();
    discarded.discard();
    drop(discarded);
    client
        .sign_identity(&identities[0], &request, auth(&pin), None)
        .unwrap();
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                client
                    .sign_identity(&identities[0], &request, auth(&pin), None)
                    .unwrap();
            });
        }
    });
    drop(client);
    // Always-authenticate needs combined token mechanisms and a per-operation PIN.
    let client = connect(&module, HashingPolicy::TokenOnly);
    let key = client
        .private_key(uri("always", "private"), auth(&pin))
        .unwrap();
    let certificate = client
        .certificate(uri("always", "cert"), auth(&pin))
        .unwrap();
    assert!(matches!(
        client.sign(&key, &request, auth(&pin), None),
        Err(Error::Runtime(RuntimeError::ContextAuthenticationRequired))
    ));
    assert!(
        client
            .sign(&key, &request, auth(&pin), Some(Pin::Value(&bad_pin)))
            .is_err()
    );
    let identity = client
        .bind_identity(key, certificate, auth(&pin), Some(Pin::Value(&pin)))
        .unwrap();
    client
        .sign_identity(&identity, &request, auth(&pin), Some(Pin::Value(&pin)))
        .unwrap();
    drop(client);
    module.finalize().unwrap();
    // Change the key under the original stable selector, keeping the old certificate.
    // Reopen the module so no provider object cache can hide the replacement.
    key_tool(
        &path,
        &["--delete-object", "--type", "privkey", "--id", "01"],
    );
    key_tool(
        &path,
        &["--delete-object", "--type", "pubkey", "--id", "01"],
    );
    key_tool(
        &path,
        &[
            "--keypairgen",
            "--key-type",
            "RSA:2048",
            "--id",
            "01",
            "--label",
            "rsa",
            "--usage-sign",
            "--sensitive",
        ],
    );
    let module = Module::load(&path).unwrap();
    let client = connect(&module, HashingPolicy::SoftwareOnly);
    assert!(matches!(
        client.sign_identity(&identities[0], &request, auth(&pin), None),
        Err(Error::KeyCertificateMismatch)
    ));
    // Mismatch discarded its lease; a different bound identity still works.
    let ec_request = SignRequest {
        algorithm: SignatureAlgorithm::Ecdsa,
        ..request
    };
    client
        .sign_identity(&identities[1], &ec_request, auth(&pin), None)
        .unwrap();
    drop(client);
    module.finalize().unwrap();
}

fn runtime_mutation_guards(path: &str) {
    use pkcs11_runtime::*;
    let module = Module::load(path).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=client-test".parse().unwrap())
        .unwrap();
    let pin = secrecy::SecretString::from("12345678");
    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
    assert!(matches!(
        session.create_object(&[]),
        Err(Error::ReadWriteRequired)
    ));
    session.info().unwrap();
    session.close().unwrap();
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    let reference = ObjectRef::new(
        "pkcs11:token=client-test;object=rsa;type=private"
            .parse()
            .unwrap(),
    )
    .unwrap();
    assert!(
        session
            .resolve(&reference)
            .unwrap()
            .update_attributes(&[Attribute::Class(ObjectClass::DATA)])
            .is_err()
    );
    assert!(matches!(session.info(), Err(Error::Closed)));
    session.close().unwrap();
    module.finalize().unwrap();
}

#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn management_workflows() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let path = std::env::var("PKCS11_TEST_MODULE").unwrap();
    let provider = Provider::load(&path).unwrap();
    let location: Pkcs11Uri = "pkcs11:token=client-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let bad_pin = SecretString::from("incorrect");
    let tokens = provider.tokens().unwrap();
    let token = tokens
        .iter()
        .find(|t| t.info.label() == "client-test")
        .unwrap();
    assert!(
        provider
            .slots(true)
            .unwrap()
            .iter()
            .any(|s| s.id == token.slot_id)
    );
    assert!(
        !provider
            .mechanisms(&token.uri().unwrap())
            .unwrap()
            .is_empty()
    );
    assert!(
        provider
            .management(&location, SessionMode::ReadOnly, auth(&bad_pin))
            .is_err()
    );
    let count = std::cell::Cell::new(0);
    let diagnostic = provider
        .diagnose(
            &location,
            SessionMode::ReadOnly,
            NonZeroUsize::new(3).unwrap(),
            || {
                count.set(count.get() + 1);
                auth(&pin)
            },
        )
        .unwrap();
    assert_eq!(count.get(), 4);
    assert_eq!(diagnostic.capacity, 3);
    assert!(diagnostic.exhaustion_verified && diagnostic.reuse_verified);
    let mut ro = provider
        .management(&location, SessionMode::ReadOnly, Authentication::None)
        .unwrap();
    assert_eq!(
        ro.import_data(b"no write", b"x", b"refactor-ro")
            .unwrap_err()
            .kind(),
        ErrorKind::Policy
    );
    assert!(!ro.objects(&[AttributeType::Class]).unwrap().is_empty());
    for length in [1, 32, 1024, RandomRequest::MAXIMUM] {
        let bytes = ro
            .generate_random(RandomRequest::new(length).unwrap())
            .unwrap();
        assert_eq!(secrecy::ExposeSecret::expose_secret(&bytes).len(), length);
        assert!(format!("{bytes:?}").contains("REDACTED"));
    }
    ro.close().unwrap();
    let mut session = provider
        .management(&location, SessionMode::ReadWrite, auth(&pin))
        .unwrap();
    let data = object_reference(uri("refactor-data", "data")).unwrap();
    let bytes = b"binary\0payload\xff";
    session
        .import_data(bytes, b"\x00\xff", b"refactor-data")
        .unwrap();
    assert_eq!(session.export_value(&data).unwrap(), bytes);
    let attrs = session
        .inspect(
            &data,
            &[
                AttributeType::ObjectId,
                AttributeType::Value,
                AttributeType::Modulus,
            ],
        )
        .unwrap();
    assert!(matches!(attrs[0].status, AttributeInfo::Available(_)));
    assert!(
        attrs[0]
            .values
            .as_ref()
            .unwrap()
            .expose_values()
            .contains(&Attribute::ObjectId(vec![0, 255]))
    );
    assert!(!format!("{attrs:?}").contains("payload"));
    assert!(matches!(attrs[2].status, AttributeInfo::TypeInvalid));
    session.set_label(&data, b"refactor-renamed").unwrap();
    let renamed = object_reference(uri("refactor-renamed", "data")).unwrap();
    assert_eq!(session.export_value(&renamed).unwrap(), bytes);
    session.delete(&renamed).unwrap();
    // Raw import/export supports certificates outside the signing API's algorithms.
    let der = include_bytes!("fixtures/ed25519.der").to_vec();
    let document = CertificateDocument::from_der(der.clone()).unwrap();
    session
        .import_certificate(&document, b"\xfe", b"refactor-cert")
        .unwrap();
    let cert = object_reference(uri("refactor-cert", "cert")).unwrap();
    assert_eq!(session.export_value(&cert).unwrap(), der);
    session.delete(&cert).unwrap();
    session
        .generate_signing_key_pair(
            KeyKind::Ec(NamedCurve::P256),
            b"\xfe",
            b"refactor-key",
            false,
        )
        .unwrap();
    let private = object_reference(uri("refactor-key", "private")).unwrap();
    let attrs = session
        .inspect(
            &private,
            &[AttributeType::Sensitive, AttributeType::Extractable],
        )
        .unwrap();
    assert!(
        attrs[0]
            .values
            .as_ref()
            .unwrap()
            .expose_values()
            .contains(&Attribute::Sensitive(true))
    );
    assert!(
        attrs[1]
            .values
            .as_ref()
            .unwrap()
            .expose_values()
            .contains(&Attribute::Extractable(false))
    );
    assert!(matches!(
        session.export_value(&private),
        Err(Error::UnsupportedExport)
    ));
    // A signing client and management session share the same initialization owner.
    let client = provider
        .client(
            &location,
            NonZeroUsize::new(1).unwrap(),
            SigningPolicy {
                hashing: HashingPolicy::SoftwareOnly,
                ..Default::default()
            },
        )
        .unwrap();
    let key = client
        .private_key(uri("refactor-key", "private"), Authentication::None)
        .unwrap();
    assert_eq!(
        client.capabilities(&key, Authentication::None).unwrap().key,
        KeyKind::Ec(NamedCurve::P256)
    );
    drop(client);
    session.delete(&private).unwrap();
    session
        .delete(&object_reference(uri("refactor-key", "public")).unwrap())
        .unwrap();
    // Ambiguous selectors never perform a mutation; a completed search stays usable.
    session
        .import_data(b"first", b"1", b"refactor-duplicate")
        .unwrap();
    session
        .import_data(b"second", b"2", b"refactor-duplicate")
        .unwrap();
    let duplicate = object_reference(uri("refactor-duplicate", "data")).unwrap();
    assert_eq!(
        session.delete(&duplicate).unwrap_err().kind(),
        ErrorKind::Selection
    );
    assert!(!session.objects(&[AttributeType::Class]).unwrap().is_empty());
    session.close().unwrap();
    let mut session = provider
        .management(&location, SessionMode::ReadWrite, auth(&pin))
        .unwrap();
    let duplicates = session
        .objects(&[AttributeType::Label])
        .unwrap()
        .into_iter()
        .filter(|attrs| {
            attrs[0].values.as_ref().is_some_and(|v| {
                v.expose_values()
                    .contains(&Attribute::Label(b"refactor-duplicate".to_vec()))
            })
        })
        .count();
    assert_eq!(duplicates, 2);
    session.close().unwrap();
    let mut owned = provider
        .management_owned(&location, SessionMode::ReadWrite, Authentication::None)
        .unwrap();
    assert_eq!(owned.state().unwrap(), SessionState::RwPublic);
    owned.authenticate(auth(&pin)).unwrap();
    assert_eq!(owned.state().unwrap(), SessionState::RwUser);
    let read = provider
        .management(&location, SessionMode::ReadOnly, Authentication::None)
        .unwrap();
    assert_eq!(read.state().unwrap(), SessionState::RoUser);
    read.close().unwrap();
    assert_eq!(owned.state().unwrap(), SessionState::RwUser);
    owned.logout().unwrap();
    assert_eq!(owned.state().unwrap(), SessionState::RwPublic);
    let so = SecretString::from("87654321");
    owned
        .authenticate(Authentication::SecurityOfficer(Pin::Value(&so)))
        .unwrap();
    assert_eq!(owned.state().unwrap(), SessionState::RwSecurityOfficer);
    owned.logout().unwrap();
    // An owned session keeps initialization alive after its Provider is dropped.
    drop(provider);
    assert_eq!(owned.state().unwrap(), SessionState::RwPublic);
    owned.close().unwrap();
    let mut provider = Provider::load(&path).unwrap();
    let owned = provider
        .management_owned(&location, SessionMode::ReadOnly, Authentication::None)
        .unwrap();
    assert!(matches!(
        provider.initialize_token(0, &so, "must-not-erase"),
        Err(Error::ProviderInUse)
    ));
    assert!(matches!(provider.finalize(), Err(Error::ProviderInUse)));
    assert_eq!(owned.state().unwrap(), SessionState::RoPublic);
    owned.close().unwrap();
    let provider = Provider::load(&path).unwrap();
    provider.finalize().unwrap();
    runtime_mutation_guards(&path);
}

#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn scoped_signing_choices_signature_and_explicit_close() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let pin = SecretString::from("12345678");
    let token = "pkcs11:token=client-test".parse().unwrap();
    let key = PrivateKeyRef::new(uri("p256", "private")).unwrap();
    let certificate = object_reference(uri("p256", "cert")).unwrap();
    let policy = SigningPolicy {
        hashing: HashingPolicy::SoftwareOnly,
        ..SigningPolicy::default()
    };
    let mut session = provider
        .management(&token, SessionMode::ReadOnly, auth(&pin))
        .unwrap();
    let certificate = Certificate::from_der(session.export_public(&certificate).unwrap()).unwrap();
    let choices = session.signing_options(&key, &policy).unwrap();
    let choice = choices
        .choices
        .iter()
        .find(|choice| {
            choice.parameters.algorithm == SignatureAlgorithm::Ecdsa
                && choice.parameters.digest == DigestAlgorithm::Sha256
        })
        .unwrap();
    assert_eq!(choice.hashing, HashLocation::Software);
    let request = choice
        .parameters
        .request(SignInput::Message(b"scoped signing"));
    let signature = session.sign(&key, &request, &policy, None).unwrap();
    session.close().unwrap();
    certificate.verify_signature(&request, &signature).unwrap();
    provider.finalize().unwrap();
}
