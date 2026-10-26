// SPDX-License-Identifier: MIT OR Apache-2.0
//! Full TLS handshakes against isolated, nonextractable software-token keys.
mod common;
use common::transfer;
use pkcs11_runtime::{
    Attribute, AttributeType, Authentication, HashingPolicy, KeyKind, Module, ObjectRef, Pin,
    PrivateKeyRef, SessionMode, SessionPool, SigningPolicy,
};
use pkcs11_rustls_adapter::{
    ClientResolver, Credential, CredentialSource, Credentials, Error, PinInput, ServerResolver,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, SignatureScheme,
    client::ResolvesClientCert, crypto::CryptoProvider,
};
use rustls_pki_types::{CertificateDer, ServerName};
use secrecy::SecretString;
use std::{
    io::{Read, Write},
    num::NonZeroUsize,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use x509_cert::der::{Decode, Encode};

fn source(context: bool) -> Arc<dyn CredentialSource> {
    Arc::new(move || {
        Ok(Credentials {
            user: Some(PinInput::Value(SecretString::from("12345678"))),
            context: context.then(|| PinInput::Value(SecretString::from("12345678"))),
        })
    })
}
fn key(label: &str) -> PrivateKeyRef {
    PrivateKeyRef::new(
        format!("pkcs11:token=tls-test;object={label};type=private")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn cert(root: &std::path::Path, label: &str) -> CertificateDer<'static> {
    CertificateDer::from(std::fs::read(root.join(format!("{label}.der"))).unwrap())
}
fn credential(
    pool: &Arc<SessionPool<'static>>,
    root: &std::path::Path,
    label: &str,
    provider: &Arc<CryptoProvider>,
) -> Arc<Credential> {
    Arc::new(
        Credential::load(
            pool.clone(),
            key(label),
            vec![cert(root, label), cert(root, "ca")],
            SigningPolicy {
                hashing: if label.contains('p') {
                    HashingPolicy::SoftwareOnly
                } else {
                    HashingPolicy::TokenOnly
                },
                ..Default::default()
            },
            source(label == "server-always"),
            provider.clone(),
        )
        .unwrap(),
    )
}
fn roots(ca: CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();
    roots
}
fn configs(
    provider: &Arc<CryptoProvider>,
    version: &'static rustls::SupportedProtocolVersion,
    server: Arc<dyn rustls::server::ResolvesServerCert>,
    client: Arc<dyn ResolvesClientCert>,
    server_root: CertificateDer<'static>,
    client_root: Option<CertificateDer<'static>>,
) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let cb = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .unwrap();
    let client = cb
        .with_root_certificates(roots(server_root))
        .with_client_cert_resolver(client);
    let sb = pkcs11_rustls_adapter::server_config_builder(provider.clone(), &[version]).unwrap();
    let server = match client_root {
        Some(root) => sb
            .with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots(root)),
                    provider.clone(),
                )
                .build()
                .unwrap(),
            )
            .with_cert_resolver(server),
        None => sb.with_no_client_auth().with_cert_resolver(server),
    };
    (Arc::new(client), Arc::new(server))
}
fn handshake(
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    name: &str,
) -> Result<(), rustls::Error> {
    let mut c = ClientConnection::new(client, ServerName::try_from(name.to_owned()).unwrap())?;
    let mut s = ServerConnection::new(server)?;
    for _ in 0..64 {
        transfer(&mut c, &mut s)?;
        if !c.is_handshaking() && !s.is_handshaking() {
            c.writer().write_all(b"request").unwrap();
            transfer(&mut c, &mut s)?;
            let mut request = [0; 7];
            s.reader().read_exact(&mut request).unwrap();
            assert_eq!(&request, b"request");
            s.writer().write_all(b"response").unwrap();
            transfer(&mut c, &mut s)?;
            let mut response = [0; 8];
            c.reader().read_exact(&mut response).unwrap();
            assert_eq!(&response, b"response");
            assert!(c.peer_certificates().is_some());
            assert_eq!(c.protocol_version(), s.protocol_version());
            return Ok(());
        }
    }
    Err(rustls::Error::General("test handshake stalled".into()))
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn token_tls_handshakes_and_lifecycle() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let path = std::env::var("PKCS11_TEST_MODULE").unwrap();
    let root = PathBuf::from(std::env::var("PKCS11_TLS_TEST_DIR").unwrap());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let module = Arc::new(Module::load(&path).unwrap());
    {
        let pool = Arc::new(
            SessionPool::new_owned(
                module.clone(),
                &"pkcs11:token=tls-test".parse().unwrap(),
                SessionMode::ReadOnly,
                NonZeroUsize::new(4).unwrap(),
            )
            .unwrap(),
        );
        {
            let pin = SecretString::from("12345678");
            let mut lease = pool
                .try_acquire(Authentication::User(Pin::Value(&pin)))
                .unwrap();
            for label in [
                "server-rsa",
                "server-p256",
                "server-p384",
                "server-p521",
                "client-rsa",
                "client-p256",
                "server-always",
                "server-wrong",
            ] {
                let reference = key(label);
                let attributes = lease
                    .session()
                    .resolve(reference.as_object_ref())
                    .unwrap()
                    .read_attributes(&[AttributeType::Sensitive, AttributeType::Extractable])
                    .unwrap();
                assert!(
                    attributes
                        .expose_values()
                        .contains(&Attribute::Sensitive(true))
                );
                assert!(
                    attributes
                        .expose_values()
                        .contains(&Attribute::Extractable(false))
                );
            }
        }
        let rsa = credential(&pool, &root, "server-rsa", &provider);
        let p256 = credential(&pool, &root, "server-p256", &provider);
        let p384 = credential(&pool, &root, "server-p384", &provider);
        let always = credential(&pool, &root, "server-always", &provider);
        let client_rsa = credential(&pool, &root, "client-rsa", &provider);
        let client_ec = credential(&pool, &root, "client-p256", &provider);
        // EC leaf certificates are CA-signed with RSA; key selection must still be EC.
        assert_eq!(
            p256.certified_key().key.algorithm(),
            rustls::SignatureAlgorithm::ECDSA
        );
        assert!(rsa.certified_key().keys_match().is_ok());
        assert!(
            p256.certified_key()
                .key
                .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                .is_none()
        );
        assert!(
            p256.certified_key()
                .key
                .choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
                .is_none()
        );
        assert!(matches!(
            Credential::load(
                pool.clone(),
                key("server-p521"),
                vec![cert(&root, "server-p521")],
                SigningPolicy {
                    hashing: HashingPolicy::SoftwareOnly,
                    ..Default::default()
                },
                source(false),
                provider.clone()
            ),
            Err(Error::NoCompatibleScheme)
        ));
        assert!(matches!(
            Credential::load(
                pool.clone(),
                key("server-rsa"),
                vec![cert(&root, "server-wrong")],
                SigningPolicy::default(),
                source(false),
                provider.clone()
            ),
            Err(Error::KeyCertificateMismatch)
        ));
        assert!(matches!(
            Credential::load(
                pool.clone(),
                key("server-rsa"),
                vec![],
                SigningPolicy::default(),
                source(false),
                provider.clone()
            ),
            Err(Error::EmptyChain)
        ));
        let resolver = Arc::new(
            ServerResolver::new(
                vec![
                    ("localhost".into(), rsa.clone()),
                    ("LOCALHOST".into(), p256.clone()),
                ],
                Some(rsa.clone()),
            )
            .unwrap(),
        );
        assert!(
            resolver
                .select(Some("unknown.example"), &[SignatureScheme::RSA_PSS_SHA256])
                .is_none()
        );
        assert!(
            resolver
                .select(None, &[SignatureScheme::RSA_PSS_SHA256])
                .is_some()
        );
        assert_eq!(
            resolver
                .select(Some("LOCALHOST"), &[SignatureScheme::ECDSA_NISTP256_SHA256])
                .unwrap()
                .key
                .algorithm(),
            rustls::SignatureAlgorithm::ECDSA
        );
        assert!(matches!(
            ServerResolver::new(vec![("wrong.example".into(), rsa.clone())], None),
            Err(Error::ServerNameMismatch)
        ));
        let clients = Arc::new(ClientResolver::new(vec![
            client_ec.clone(),
            client_rsa.clone(),
        ]));
        assert!(clients.has_certs());
        assert!(
            clients
                .resolve(&[], &[SignatureScheme::RSA_PSS_SHA256])
                .is_some()
        );
        assert!(
            clients
                .resolve(&[b"unrelated issuer"], &[SignatureScheme::RSA_PSS_SHA256])
                .is_none()
        );
        let ca = x509_cert::Certificate::from_der(cert(&root, "ca").as_ref()).unwrap();
        let hint = ca.tbs_certificate.subject.to_der().unwrap();
        assert!(
            clients
                .resolve(&[&hint], &[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_some()
        );
        let empty = Arc::new(ClientResolver::new(vec![]));
        assert!(!empty.has_certs());
        let pkcs1 = Arc::new(
            Credential::load(
                pool.clone(),
                key("server-rsa"),
                vec![cert(&root, "server-rsa"), cert(&root, "ca")],
                SigningPolicy {
                    algorithms: vec![pkcs11_runtime::SignatureAlgorithm::RsaPkcs1],
                    ..Default::default()
                },
                source(false),
                provider.clone(),
            )
            .unwrap(),
        );
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let (c, s) = configs(
                &provider,
                version,
                Arc::new(
                    ServerResolver::new(vec![("localhost".into(), pkcs1.clone())], None).unwrap(),
                ),
                empty.clone(),
                cert(&root, "ca"),
                None,
            );
            let result = handshake(c, s, "localhost");
            if version.version == rustls::ProtocolVersion::TLSv1_2 {
                result.unwrap();
            } else {
                assert!(result.is_err());
            }
        }
        let (mut c, s) = configs(
            &provider,
            &rustls::version::TLS13,
            resolver.clone(),
            empty.clone(),
            cert(&root, "ca"),
            None,
        );
        Arc::get_mut(&mut c).unwrap().enable_sni = false;
        handshake(c, s, "localhost").unwrap();
        // A dual-version client can offer RSA signatures for TLS 1.3 while its
        // TLS 1.2 suites authenticate only with ECDSA.
        let mut mixed_provider = (*provider).clone();
        mixed_provider.cipher_suites.retain(|suite| {
            suite.version().version == rustls::ProtocolVersion::TLSv1_3
                || suite.usable_for_signature_algorithm(rustls::SignatureAlgorithm::ECDSA)
        });
        let mixed_client = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(mixed_provider))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .unwrap()
                .with_root_certificates(roots(cert(&root, "ca")))
                .with_no_client_auth(),
        );
        let (_, tls12_server) = configs(
            &provider,
            &rustls::version::TLS12,
            resolver.clone(),
            empty.clone(),
            cert(&root, "ca"),
            None,
        );
        handshake(mixed_client, tls12_server, "localhost").unwrap();
        for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
            for server in [&rsa, &p256, &p384, &always] {
                let server = Arc::new(
                    ServerResolver::new(vec![("localhost".into(), (*server).clone())], None)
                        .unwrap(),
                );
                let (c, s) = configs(
                    &provider,
                    version,
                    server.clone(),
                    empty.clone(),
                    cert(&root, "ca"),
                    None,
                );
                handshake(c, s, "localhost").unwrap();
                for client in [&client_rsa, &client_ec] {
                    let (c, s) = configs(
                        &provider,
                        version,
                        server.clone(),
                        Arc::new(ClientResolver::new(vec![(*client).clone()])),
                        cert(&root, "ca"),
                        Some(cert(&root, "ca")),
                    );
                    handshake(c, s, "localhost").unwrap();
                }
            }
        }
        let (c, s) = configs(
            &provider,
            &rustls::version::TLS13,
            resolver.clone(),
            clients.clone(),
            cert(&root, "other-ca"),
            None,
        );
        assert!(handshake(c, s, "localhost").is_err());
        let (c, s) = configs(
            &provider,
            &rustls::version::TLS13,
            resolver.clone(),
            clients.clone(),
            cert(&root, "ca"),
            Some(cert(&root, "other-ca")),
        );
        assert!(handshake(c, s, "localhost").is_err());
        let (c, s) = configs(
            &provider,
            &rustls::version::TLS13,
            resolver.clone(),
            empty.clone(),
            cert(&root, "ca"),
            Some(cert(&root, "ca")),
        );
        assert!(handshake(c, s, "localhost").is_err());
        let (c, s) = configs(
            &provider,
            &rustls::version::TLS13,
            resolver.clone(),
            clients.clone(),
            cert(&root, "ca"),
            None,
        );
        assert!(handshake(c, s, "unknown.example").is_err());
        let (c, s) = configs(
            &provider,
            &rustls::version::TLS13,
            resolver.clone(),
            clients.clone(),
            cert(&root, "ca"),
            Some(cert(&root, "ca")),
        );
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let c = c.clone();
                let s = s.clone();
                let b = &barrier;
                scope.spawn(move || {
                    b.wait();
                    handshake(c, s, "localhost").unwrap();
                });
            }
        });
        let signer = rsa
            .certified_key()
            .key
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .unwrap();
        let mut leases = Vec::new();
        for _ in 0..4 {
            leases.push(pool.try_acquire(Authentication::None).unwrap());
        }
        assert!(signer.sign(b"exhausted").is_err());
        drop(leases);
        signer.sign(b"recovered").unwrap();
        let mut lease = pool.try_acquire(Authentication::None).unwrap();
        lease.discard();
        drop(lease);
        signer.sign(b"reopened").unwrap();
        let missing_context = Credential::load(
            pool.clone(),
            key("server-always"),
            vec![cert(&root, "server-always")],
            SigningPolicy::default(),
            source(false),
            provider.clone(),
        );
        assert!(matches!(
            missing_context,
            Err(Error::Runtime(
                pkcs11_runtime::Error::ContextAuthenticationRequired
            ))
        ));
        let failing: Arc<dyn CredentialSource> = Arc::new(|| Err(Error::CredentialsUnavailable));
        assert!(matches!(
            Credential::load(
                pool.clone(),
                key("server-rsa"),
                vec![cert(&root, "server-rsa")],
                SigningPolicy::default(),
                failing,
                provider.clone()
            ),
            Err(Error::CredentialsUnavailable)
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let changing: Arc<dyn CredentialSource> = Arc::new(move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            Ok(Credentials {
                user: Some(PinInput::Value(SecretString::from("12345678"))),
                context: Some(PinInput::Value(SecretString::from(if n == 1 {
                    "incorrect"
                } else {
                    "12345678"
                }))),
            })
        });
        let changing = Credential::load(
            pool.clone(),
            key("server-always"),
            vec![cert(&root, "server-always")],
            SigningPolicy::default(),
            changing,
            provider.clone(),
        )
        .unwrap();
        let changing_signer = changing
            .certified_key()
            .key
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(changing_signer.sign(b"bad context PIN").is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        changing_signer.sign(b"good context PIN").unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        // Mutate under the same owner to avoid provider cross-process cache assumptions.
        let victim = credential(&pool, &root, "server-wrong", &provider);
        let victim_signer = victim
            .certified_key()
            .key
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=tls-test".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
        let reference = key("server-wrong");
        let values = session
            .resolve(reference.as_object_ref())
            .unwrap()
            .read_attributes(&[AttributeType::Extractable, AttributeType::Sensitive])
            .unwrap();
        assert!(
            values
                .expose_values()
                .contains(&Attribute::Extractable(false))
        );
        assert!(values.expose_values().contains(&Attribute::Sensitive(true)));
        session
            .resolve(reference.as_object_ref())
            .unwrap()
            .destroy()
            .unwrap();
        let public = ObjectRef::new(
            "pkcs11:token=tls-test;object=server-wrong;type=public"
                .parse()
                .unwrap(),
        )
        .unwrap();
        session.resolve(&public).unwrap().destroy().unwrap();
        session
            .generate_signing_key_pair(KeyKind::Rsa { bits: 2048 }, &[7], b"server-wrong", false)
            .unwrap();
        session.close().unwrap();
        let error = victim_signer.sign(b"replacement").unwrap_err().to_string();
        assert!(error.contains("does not match certificate"));
        assert!(!error.contains("12345678"));
        signer.sign(b"unrelated identity remains usable").unwrap();
        assert!(Arc::strong_count(&module) > 1);
    }
    assert_eq!(Arc::strong_count(&module), 1);
    Arc::try_unwrap(module).unwrap().finalize().unwrap();
    // The owned pool alone keeps initialization alive and closes before finalization.
    let module = Arc::new(Module::load(&path).unwrap());
    let weak = Arc::downgrade(&module);
    let pool = SessionPool::new_owned(
        module.clone(),
        &"pkcs11:token=tls-test".parse().unwrap(),
        SessionMode::ReadOnly,
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    drop(module);
    pool.try_acquire(Authentication::None)
        .unwrap()
        .session()
        .info()
        .unwrap();
    assert!(weak.upgrade().is_some());
    drop(pool);
    assert!(weak.upgrade().is_none());
    Module::load(&path).unwrap().finalize().unwrap();
}
