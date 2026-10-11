// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real software-token operations; independent OpenSSL verification is test-only.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::ObjectHandle,
    session::UserType,
};
use pkcs11_locator::Pkcs11Uri;
use pkcs11_runtime::*;
use secrecy::SecretString;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{
    num::NonZeroUsize,
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
};

fn uri(serial: &str, label: &str, kind: &str) -> Pkcs11Uri {
    Pkcs11Uri::builder()
        .path_attribute("serial", serial.as_bytes())
        .unwrap()
        .path_attribute("object", label.as_bytes())
        .unwrap()
        .path_attribute("type", kind.as_bytes())
        .unwrap()
        .build()
        .unwrap()
}
fn reference(serial: &str, label: &str) -> PrivateKeyRef {
    PrivateKeyRef::new(uri(serial, label, "private")).unwrap()
}
// Minimal test-only DER construction to feed an independent verifier. Runtime
// never converts ECDSA to a protocol encoding or uses these encoders.
fn der(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if data.len() < 128 {
        result.push(data.len() as u8);
    } else {
        let len = data.len().to_be_bytes();
        let first = len.iter().position(|b| *b != 0).unwrap();
        result.push(0x80 | (len.len() - first) as u8);
        result.extend_from_slice(&len[first..]);
    }
    result.extend_from_slice(data);
    result
}
fn integer(bytes: &[u8]) -> Vec<u8> {
    let bytes = &bytes[bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1)..];
    let mut value = Vec::new();
    if bytes[0] & 0x80 != 0 {
        value.push(0);
    }
    value.extend_from_slice(bytes);
    der(2, &value)
}
fn public_der(
    session: &cryptoki::session::Session,
    handle: ObjectHandle,
    params: Option<&[u8]>,
) -> Vec<u8> {
    let (algorithm, bits) = if let Some(params) = params {
        let values = session
            .get_attributes(handle, &[AttributeType::EcPoint])
            .unwrap();
        let Attribute::EcPoint(point) = &values[0] else {
            panic!("point")
        };
        // SoftHSM returns an uncompressed point wrapped in a DER OCTET STRING.
        let start = if point[1] < 128 {
            2
        } else {
            2 + (point[1] & 127) as usize
        };
        let mut algorithm = vec![6, 7, 42, 134, 72, 206, 61, 2, 1];
        algorithm.extend_from_slice(params);
        (der(0x30, &algorithm), point[start..].to_vec())
    } else {
        let values = session
            .get_attributes(
                handle,
                &[AttributeType::Modulus, AttributeType::PublicExponent],
            )
            .unwrap();
        let mut data = Vec::new();
        for value in values {
            match value {
                Attribute::Modulus(v) | Attribute::PublicExponent(v) => data.extend(integer(&v)),
                _ => panic!("RSA public material"),
            }
        }
        (
            vec![0x30, 0x0d, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0],
            der(0x30, &data),
        )
    };
    let mut body = algorithm;
    let mut value = vec![0];
    value.extend(bits);
    body.extend(der(3, &value));
    der(0x30, &body)
}
fn make_key(
    session: &cryptoki::session::Session,
    label: &str,
    params: Option<&[u8]>,
    extra: &[Attribute],
) -> Vec<u8> {
    let mut public = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(label.as_bytes().to_vec()),
        Attribute::Verify(true),
    ];
    let mut private = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(label.as_bytes().to_vec()),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
    ];
    for attr in extra {
        private.retain(|a| a.attribute_type() != attr.attribute_type());
        private.push(attr.clone());
    }
    let mechanism = if let Some(params) = params {
        public.push(Attribute::EcParams(params.to_vec()));
        Mechanism::EccKeyPairGen
    } else {
        public.extend([
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![1, 0, 1]),
        ]);
        Mechanism::RsaPkcsKeyPairGen
    };
    let (public_handle, _) = session
        .generate_key_pair(&mechanism, &public, &private)
        .unwrap();
    public_der(session, public_handle, params)
}
static NEXT: AtomicUsize = AtomicUsize::new(0);
fn verify(root: &Path, key: &[u8], request: &SignRequest<'_>, message: &[u8], signature: &[u8]) {
    let dir = root.join(format!("verify-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("key.der"), key).unwrap();
    let signature = if request.algorithm == SignatureAlgorithm::Ecdsa {
        let half = signature.len() / 2;
        let mut body = integer(&signature[..half]);
        body.extend(integer(&signature[half..]));
        der(0x30, &body)
    } else {
        signature.to_vec()
    };
    std::fs::write(dir.join("signature"), signature).unwrap();
    std::fs::write(dir.join("message"), message).unwrap();
    let digest = match request.digest {
        DigestAlgorithm::Sha256 => "-sha256",
        DigestAlgorithm::Sha384 => "-sha384",
        DigestAlgorithm::Sha512 => "-sha512",
    };
    let mut command = Command::new("openssl");
    command.current_dir(&dir).args([
        "dgst",
        digest,
        "-verify",
        "key.der",
        "-keyform",
        "DER",
        "-signature",
        "signature",
    ]);
    if let Some(pss) = request.pss {
        let mgf = match pss.mgf_digest {
            DigestAlgorithm::Sha256 => "sha256",
            DigestAlgorithm::Sha384 => "sha384",
            DigestAlgorithm::Sha512 => "sha512",
        };
        command.args([
            "-sigopt",
            "rsa_padding_mode:pss",
            "-sigopt",
            &format!("rsa_pss_saltlen:{}", pss.salt_len),
            "-sigopt",
            &format!("rsa_mgf1_md:{mgf}"),
        ]);
    }
    command.arg("message");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "OpenSSL verification failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(dir.join("message"), b"altered message").unwrap();
    assert!(
        !command.output().unwrap().status.success(),
        "tampered message verified"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
#[ignore = "requires tools/test-softhsm.sh and OpenSSL"]
fn pooled_signing_and_recovery() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let path = std::env::var("PKCS11_TEST_MODULE").unwrap();
    let config = std::env::var("SOFTHSM2_CONF").unwrap();
    let root = Path::new(&config).parent().unwrap();
    let user = SecretString::from("12345678");
    let fixture = Pkcs11::new(&path).unwrap();
    fixture
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = fixture.get_slots_with_initialized_token().unwrap()[0];
    let serial = fixture
        .get_token_info(slot)
        .unwrap()
        .serial_number()
        .to_owned();
    let raw = fixture.open_rw_session(slot).unwrap();
    raw.login(UserType::User, Some(&user)).unwrap();
    let rsa = make_key(&raw, "stage4-rsa", None, &[]);
    let restricted = make_key(
        &raw,
        "stage4-restricted",
        None,
        &[Attribute::AllowedMechanisms(vec![MechanismType::RSA_PKCS])],
    );
    let auth = make_key(
        &raw,
        "stage4-auth",
        None,
        &[Attribute::AlwaysAuthenticate(true)],
    );
    let multi_restricted = make_key(
        &raw,
        "review-multi-restricted",
        None,
        &[Attribute::AllowedMechanisms(vec![
            MechanismType::RSA_PKCS,
            MechanismType::SHA256_RSA_PKCS,
        ])],
    );
    make_key(&raw, "stage4-nosign", None, &[Attribute::Sign(false)]);
    let curves = [
        vec![6, 8, 42, 134, 72, 206, 61, 3, 1, 7],
        vec![6, 5, 43, 129, 4, 0, 34],
        vec![6, 5, 43, 129, 4, 0, 35],
    ];
    let ec: Vec<_> = curves
        .iter()
        .enumerate()
        .map(|(i, params)| make_key(&raw, &format!("stage4-ec{i}"), Some(params), &[]))
        .collect();
    let ec_auth = make_key(
        &raw,
        "review-ec-auth",
        Some(&curves[0]),
        &[Attribute::AlwaysAuthenticate(true)],
    );
    raw.close().unwrap();
    fixture.finalize().unwrap();
    let module = Module::load(&path).unwrap();
    let selector = uri(&serial, "stage4-rsa", "private");
    let token = module.resolve_token(selector.token_selector()).unwrap();
    let pool = SessionPool::new(token, SessionMode::ReadOnly, NonZeroUsize::new(3).unwrap());
    let key = reference(&serial, "stage4-rsa");
    let mut lease = pool
        .try_acquire(Authentication::User(Pin::Value(&user)))
        .unwrap();
    let first = lease.generation();
    let req = SignRequest {
        algorithm: SignatureAlgorithm::RsaPkcs1,
        digest: DigestAlgorithm::Sha256,
        input: SignInput::Message(b"stage four"),
        pss: None,
    };
    let capabilities = lease.session().key_capabilities(&key).unwrap();
    assert_eq!(capabilities.key, KeyKind::Rsa { bits: 2048 });
    assert_eq!(capabilities.allowed_mechanisms, Some(vec![]));
    let metadata = key.public_metadata(lease.session()).unwrap();
    assert_eq!(metadata.public_exponent, Some(vec![1, 0, 1]));
    let public = PublicKeyRef::new(uri(&serial, "stage4-rsa", "public")).unwrap();
    assert_eq!(
        metadata.modulus,
        public.public_metadata(lease.session()).unwrap().modulus
    );
    let plan = capabilities.plan(&req, &SigningPolicy::default()).unwrap();
    assert_eq!(plan.hash_location(), HashLocation::Token);
    let signature = lease
        .session()
        .sign(&key, &req, &SigningPolicy::default(), None)
        .unwrap();
    verify(root, &rsa, &req, b"stage four", &signature);
    drop(lease);
    let mut lease = pool
        .try_acquire(Authentication::User(Pin::Value(&user)))
        .unwrap();
    assert_eq!(lease.generation(), first);
    lease.discard();
    drop(lease);
    let mut lease = pool
        .try_acquire(Authentication::User(Pin::Value(&user)))
        .unwrap();
    assert_ne!(lease.generation(), first);
    let signature = lease
        .session()
        .sign(&key, &req, &SigningPolicy::default(), None)
        .unwrap();
    verify(root, &rsa, &req, b"stage four", &signature);
    drop(lease);
    // All leases must be acquired simultaneously before any can be returned.
    // Bounded channels avoid hanging this test if a worker fails before signing.
    let (ready_tx, ready_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let mut starters = Vec::new();
        for _ in 0..3 {
            let (start_tx, start_rx) = mpsc::channel();
            starters.push(start_tx);
            let ready_tx = ready_tx.clone();
            let pool = &pool;
            let user = &user;
            let key = &key;
            let rsa = &rsa;
            scope.spawn(move || {
                let mut lease = pool
                    .try_acquire(Authentication::User(Pin::Value(user)))
                    .unwrap();
                ready_tx.send(lease.generation()).unwrap();
                start_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .unwrap();
                let signature = lease
                    .session()
                    .sign(key, &req, &SigningPolicy::default(), None)
                    .unwrap();
                verify(root, rsa, &req, b"stage four", &signature);
            });
        }
        let mut generations = Vec::new();
        for _ in 0..3 {
            generations.push(
                ready_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .unwrap(),
            );
        }
        generations.sort_unstable();
        generations.dedup();
        assert_eq!(generations.len(), 3);
        assert!(matches!(
            pool.try_acquire(Authentication::None),
            Err(Error::PoolExhausted)
        ));
        for start in starters {
            start.send(()).unwrap();
        }
    });
    let mut lease = pool
        .try_acquire(Authentication::User(Pin::Value(&user)))
        .unwrap();
    // Token-wide logout is recovered only by the caller's next authenticated checkout.
    lease.session().logout().unwrap();
    drop(lease);
    let mut lease = pool
        .try_acquire(Authentication::User(Pin::Value(&user)))
        .unwrap();
    for digest in [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ] {
        let hashed = match digest {
            DigestAlgorithm::Sha256 => Sha256::digest(b"stage four").to_vec(),
            DigestAlgorithm::Sha384 => Sha384::digest(b"stage four").to_vec(),
            DigestAlgorithm::Sha512 => Sha512::digest(b"stage four").to_vec(),
        };
        for (algorithm, public, key) in [
            (
                SignatureAlgorithm::RsaPkcs1,
                &rsa,
                reference(&serial, "stage4-rsa"),
            ),
            (
                SignatureAlgorithm::RsaPss,
                &rsa,
                reference(&serial, "stage4-rsa"),
            ),
            (
                SignatureAlgorithm::Ecdsa,
                &ec[0],
                reference(&serial, "stage4-ec0"),
            ),
        ] {
            for (input, hashing) in [
                (
                    SignInput::Message(b"stage four"),
                    HashingPolicy::AllowSoftware,
                ),
                (
                    SignInput::Message(b"stage four"),
                    HashingPolicy::SoftwareOnly,
                ),
                (SignInput::Digest(&hashed), HashingPolicy::TokenOnly),
            ] {
                let req = SignRequest {
                    algorithm,
                    digest,
                    input,
                    pss: (algorithm == SignatureAlgorithm::RsaPss).then_some(PssParameters {
                        mgf_digest: digest,
                        salt_len: digest.output_len(),
                    }),
                };
                let policy = SigningPolicy {
                    hashing,
                    ..Default::default()
                };
                let signature = lease.session().sign(&key, &req, &policy, None).unwrap();
                verify(root, public, &req, b"stage four", &signature);
            }
        }
    }
    for (i, public) in ec.iter().enumerate() {
        let key = reference(&serial, &format!("stage4-ec{i}"));
        let req = SignRequest {
            algorithm: SignatureAlgorithm::Ecdsa,
            ..req
        };
        let policy = SigningPolicy {
            hashing: HashingPolicy::AllowSoftware,
            ..Default::default()
        };
        let signature = lease.session().sign(&key, &req, &policy, None).unwrap();
        verify(root, public, &req, b"stage four", &signature);
    }
    for salt_len in [0, 20, 222] {
        let req = SignRequest {
            algorithm: SignatureAlgorithm::RsaPss,
            pss: Some(PssParameters {
                mgf_digest: DigestAlgorithm::Sha256,
                salt_len,
            }),
            ..req
        };
        let signature = lease
            .session()
            .sign(&key, &req, &SigningPolicy::default(), None)
            .unwrap();
        verify(root, &rsa, &req, b"stage four", &signature);
    }
    let restricted_key = reference(&serial, "stage4-restricted");
    assert_eq!(
        lease
            .session()
            .key_capabilities(&restricted_key)
            .unwrap()
            .allowed_mechanisms,
        Some(vec![MechanismType::RSA_PKCS])
    );
    let multi_key = reference(&serial, "review-multi-restricted");
    assert_eq!(
        lease
            .session()
            .key_capabilities(&multi_key)
            .unwrap()
            .allowed_mechanisms,
        Some(vec![
            MechanismType::RSA_PKCS,
            MechanismType::SHA256_RSA_PKCS
        ])
    );
    let signature = lease
        .session()
        .sign(&multi_key, &req, &SigningPolicy::default(), None)
        .unwrap();
    verify(root, &multi_restricted, &req, b"stage four", &signature);
    let disallowed_digest = SignRequest {
        digest: DigestAlgorithm::Sha384,
        ..req
    };
    assert!(matches!(
        lease.session().sign(
            &multi_key,
            &disallowed_digest,
            &SigningPolicy::default(),
            None
        ),
        Err(Error::UnsupportedSigning(_))
    ));
    let restriction_error = lease
        .session()
        .sign(&restricted_key, &req, &SigningPolicy::default(), None)
        .unwrap_err();
    assert!(
        matches!(restriction_error, Error::UnsupportedSigning(_)),
        "{restriction_error:?}"
    );
    let policy = SigningPolicy {
        hashing: HashingPolicy::AllowSoftware,
        ..Default::default()
    };
    let signature = lease
        .session()
        .sign(&restricted_key, &req, &policy, None)
        .unwrap();
    verify(root, &restricted, &req, b"stage four", &signature);
    assert!(
        lease
            .session()
            .sign(&reference(&serial, "stage4-nosign"), &req, &policy, None)
            .is_err()
    );
    let auth_key = reference(&serial, "stage4-auth");
    assert!(matches!(
        lease
            .session()
            .sign(&auth_key, &req, &SigningPolicy::default(), None),
        Err(Error::ContextAuthenticationRequired)
    ));
    let signature = lease
        .session()
        .sign(
            &auth_key,
            &req,
            &SigningPolicy::default(),
            Some(Pin::Value(&user)),
        )
        .unwrap();
    verify(root, &auth, &req, b"stage four", &signature);
    let auth_pss = SignRequest {
        algorithm: SignatureAlgorithm::RsaPss,
        pss: Some(PssParameters {
            mgf_digest: DigestAlgorithm::Sha256,
            salt_len: 32,
        }),
        ..req
    };
    let signature = lease
        .session()
        .sign(
            &auth_key,
            &auth_pss,
            &SigningPolicy::default(),
            Some(Pin::Value(&user)),
        )
        .unwrap();
    verify(root, &auth, &auth_pss, b"stage four", &signature);
    let ec_auth_key = reference(&serial, "review-ec-auth");
    let ec_capabilities = lease.session().key_capabilities(&ec_auth_key).unwrap();
    let mut combined_ec_checks = 0;
    for (digest, mechanism) in [
        (DigestAlgorithm::Sha256, MechanismType::ECDSA_SHA256),
        (DigestAlgorithm::Sha384, MechanismType::ECDSA_SHA384),
        (DigestAlgorithm::Sha512, MechanismType::ECDSA_SHA512),
    ] {
        let ec_request = SignRequest {
            algorithm: SignatureAlgorithm::Ecdsa,
            digest,
            ..req
        };
        if ec_capabilities
            .mechanisms
            .iter()
            .any(|m| m.mechanism == mechanism && m.can_sign)
        {
            assert!(matches!(
                lease
                    .session()
                    .sign(&ec_auth_key, &ec_request, &SigningPolicy::default(), None),
                Err(Error::ContextAuthenticationRequired)
            ));
            let result = lease.session().sign(
                &ec_auth_key,
                &ec_request,
                &SigningPolicy::default(),
                Some(Pin::Value(&user)),
            );
            match result {
                Ok(signature) => {
                    verify(root, &ec_auth, &ec_request, b"stage four", &signature);
                    combined_ec_checks += 1;
                }
                // SoftHSM 2.7 advertises these mechanisms but disables multipart
                // ECDSA. Check the exact failure and recovery, never retry signing.
                Err(Error::Backend {
                    operation: "sign update",
                    source:
                        cryptoki::error::Error::Pkcs11(
                            cryptoki::error::RvError::OperationNotInitialized,
                            cryptoki::context::Function::SignUpdate,
                        ),
                }) => {
                    let generation = lease.generation();
                    assert!(matches!(lease.session().info(), Err(Error::Closed)));
                    drop(lease);
                    lease = pool
                        .try_acquire(Authentication::User(Pin::Value(&user)))
                        .unwrap();
                    assert_ne!(lease.generation(), generation);
                }
                Err(error) => panic!("unexpected combined ECDSA error: {error}"),
            }
        }
        let raw_policy = SigningPolicy {
            hashing: HashingPolicy::SoftwareOnly,
            ..Default::default()
        };
        assert!(matches!(
            lease.session().sign(
                &ec_auth_key,
                &ec_request,
                &raw_policy,
                Some(Pin::Value(&user))
            ),
            Err(Error::UnsupportedSigning(_))
        ));
    }
    eprintln!("combined ECDSA context-authentication mechanisms verified: {combined_ec_checks}");
    if std::env::var_os("PKCS11_TEST_REQUIRE_EC_MULTIPART").is_some() {
        assert_eq!(
            combined_ec_checks, 3,
            "provider must implement multipart ECDSA"
        );
    }
    assert!(matches!(
        lease.session().sign(
            &auth_key,
            &req,
            &SigningPolicy::default(),
            Some(Pin::ProtectedPath)
        ),
        Err(Error::ProtectedPathUnavailable)
    ));
    // Failed context login leaves an initialized operation. It must be discarded.
    let generation = lease.generation();
    let wrong = SecretString::from("wrong-canary");
    assert!(matches!(
        lease.session().sign(
            &auth_key,
            &req,
            &SigningPolicy::default(),
            Some(Pin::Value(&wrong))
        ),
        Err(Error::Backend { .. })
    ));
    assert!(matches!(
        lease.session().sign(&key, &req, &policy, None),
        Err(Error::Closed)
    ));
    // A failed operation invalidates the whole session, not only its signer.
    assert!(matches!(lease.session().info(), Err(Error::Closed)));
    assert!(matches!(
        lease.session().authenticate(Authentication::None),
        Err(Error::Closed)
    ));
    assert!(matches!(
        lease.session().find_objects(&[]),
        Err(Error::Closed)
    ));
    assert!(matches!(
        lease.session().resolve(key.as_object_ref()),
        Err(Error::Closed)
    ));
    assert!(matches!(lease.session().logout(), Err(Error::Closed)));
    drop(lease);
    let mut lease = pool
        .try_acquire(Authentication::User(Pin::Value(&user)))
        .unwrap();
    assert_ne!(lease.generation(), generation);
    let signature = lease
        .session()
        .sign(
            &auth_key,
            &req,
            &SigningPolicy::default(),
            Some(Pin::Value(&user)),
        )
        .unwrap();
    verify(root, &auth, &req, b"stage four", &signature);
    // Stable selectors still reject a different token after session recreation.
    assert!(matches!(
        lease.session().sign(
            &reference("wrong-serial", "stage4-rsa"),
            &req,
            &policy,
            None
        ),
        Err(Error::NotFound("object"))
    ));
    drop(lease);
    drop(pool);
    module.finalize().unwrap();
    // New module initialization and session, same stable private-key reference.
    let module = Module::load(&path).unwrap();
    let token = module.resolve_token(selector.token_selector()).unwrap();
    let pool = SessionPool::new(token, SessionMode::ReadOnly, NonZeroUsize::new(1).unwrap());
    let wrong = SecretString::from("wrong-canary");
    assert!(
        pool.try_acquire(Authentication::User(Pin::Value(&wrong)))
            .is_err()
    );
    let mut lease = pool
        .try_acquire(Authentication::User(Pin::Value(&user)))
        .unwrap();
    let signature = lease
        .session()
        .sign(&key, &req, &SigningPolicy::default(), None)
        .unwrap();
    verify(root, &rsa, &req, b"stage four", &signature);
    drop(lease);
    // A panic unwinds a lease and returns its capacity, but not its session.
    let generation = pool.try_acquire(Authentication::None).unwrap().generation();
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _lease = pool.try_acquire(Authentication::None).unwrap();
        panic!("fixture unwind");
    }));
    assert!(panicked.is_err());
    let mut lease = pool
        .try_acquire(Authentication::User(Pin::Value(&user)))
        .unwrap();
    assert_ne!(generation, lease.generation());
    let signature = lease
        .session()
        .sign(&key, &req, &SigningPolicy::default(), None)
        .unwrap();
    verify(root, &rsa, &req, b"stage four", &signature);
    drop(lease);
    drop(pool);
    module.finalize().unwrap();
}
