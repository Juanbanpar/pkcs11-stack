// SPDX-License-Identifier: MIT OR Apache-2.0
//! TLS 1.3 with token-held ML-DSA identities and an application-selected provider.
mod common;
use common::transfer as exchange;
use pkcs11_runtime::{
    Authentication, MlDsaParameterSet, MlDsaSigningPolicy, Module, Pin, PrivateKeyRef,
    PublicKeyRef, SessionMode, SessionPool,
};
use pkcs11_rustls_adapter::{
    ClientResolver, Credential, CredentialSource, Credentials, Error, PinInput, ServerResolver,
    server_config_builder,
};
use rustls::{
    ClientConfig, ClientConnection, NamedGroup, RootCertStore, ServerConfig, ServerConnection,
    SignatureScheme,
    client::{ClientSessionMemoryCache, ClientSessionStore, Resumption},
    crypto::CryptoProvider,
};
use rustls_pki_types::{CertificateDer, ServerName};
use secrecy::SecretString;
use std::{
    io::{Read, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use x509_cert::{
    der::{
        Encode,
        asn1::{BitString, ObjectIdentifier},
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

fn openssl(args: &[&str]) {
    let out = Command::new(std::env::var_os("PKCS11_TEST_PQC_OPENSSL").unwrap())
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
fn certificate(path: &Path) -> CertificateDer<'static> {
    CertificateDer::from(std::fs::read(path).unwrap())
}
fn key(index: usize) -> PrivateKeyRef {
    PrivateKeyRef::new(
        format!("pkcs11:token=tls-pqc-test;id=%A1%{index:02X};type=private")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn source(always: bool, calls: Arc<AtomicUsize>) -> Arc<dyn CredentialSource> {
    Arc::new(move || {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(Credentials {
            user: Some(PinInput::Value(SecretString::from("12345678"))),
            context: always.then(|| PinInput::Value(SecretString::from("12345678"))),
        })
    })
}
fn configs(
    provider: Arc<CryptoProvider>,
    credential: Arc<Credential>,
    root: CertificateDer<'static>,
    mutual: bool,
    trust: bool,
    version: &'static rustls::SupportedProtocolVersion,
) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut roots = RootCertStore::empty();
    if trust {
        roots.add(root.clone()).unwrap();
    }
    let client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_cert_resolver(Arc::new(ClientResolver::new(if mutual {
            vec![credential.clone()]
        } else {
            vec![]
        })));
    let builder = server_config_builder(provider.clone(), &[version]).unwrap();
    let builder = if mutual {
        let mut roots = RootCertStore::empty();
        roots.add(root).unwrap();
        builder.with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap(),
        )
    } else {
        builder.with_no_client_auth()
    };
    let server = builder.with_cert_resolver(Arc::new(
        ServerResolver::new(vec![("localhost".into(), credential)], None).unwrap(),
    ));
    (Arc::new(client), Arc::new(server))
}
fn handshake(
    configs: (Arc<ClientConfig>, Arc<ServerConfig>),
    mutual: bool,
    hybrid: bool,
) -> Result<(), rustls::Error> {
    let mut c = ClientConnection::new(configs.0, ServerName::try_from("localhost").unwrap())?;
    let mut s = ServerConnection::new(configs.1)?;
    for _ in 0..64 {
        exchange(&mut c, &mut s)?;
        if !c.is_handshaking() && !s.is_handshaking() {
            assert_eq!(c.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
            if hybrid {
                assert_eq!(
                    c.negotiated_key_exchange_group().unwrap().name(),
                    NamedGroup::X25519MLKEM768
                );
                assert_eq!(
                    s.negotiated_key_exchange_group().unwrap().name(),
                    NamedGroup::X25519MLKEM768
                );
            }
            assert!(c.peer_certificates().is_some());
            assert_eq!(s.peer_certificates().is_some(), mutual);
            c.writer().write_all(b"request").unwrap();
            exchange(&mut c, &mut s)?;
            let mut bytes = [0; 7];
            s.reader().read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"request");
            s.writer().write_all(b"response").unwrap();
            exchange(&mut c, &mut s)?;
            let mut bytes = [0; 8];
            c.reader().read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"response");
            return Ok(());
        }
    }
    Err(rustls::Error::General("test handshake stalled".into()))
}
#[test]
#[ignore = "requires PKCS11_TEST_REQUIRE_PQC=1 tools/test-softhsm.sh"]
fn token_ml_dsa_tls13_authentication_and_hybrid_exchange() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    assert_eq!(std::env::var("PKCS11_TEST_REQUIRE_PQC").as_deref(), Ok("1"));
    let module_path = std::env::var("PKCS11_TEST_MODULE").unwrap();
    let out =
        Command::new(std::env::var_os("SOFTHSM2_UTIL").unwrap_or_else(|| "softhsm2-util".into()))
            .args([
                "--module",
                &module_path,
                "--init-token",
                "--free",
                "--label",
                "tls-pqc-test",
                "--so-pin",
                "87654321",
                "--pin",
                "12345678",
            ])
            .output()
            .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TLS_TEST_DIR").unwrap()).join("ml-dsa");
    std::fs::create_dir(&root).unwrap();
    let issuer_key = root.join("issuer.key");
    let issuer = root.join("issuer.pem");
    let ca = root.join("issuer.der");
    let ca_extensions = root.join("ca.extensions");
    std::fs::write(
        &ca_extensions,
        b"basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n",
    )
    .unwrap();
    openssl(&[
        "genpkey",
        "-algorithm",
        "ML-DSA-65",
        "-out",
        issuer_key.to_str().unwrap(),
    ]);
    openssl(&[
        "x509",
        "-new",
        "-key",
        issuer_key.to_str().unwrap(),
        "-subj",
        "/CN=TLS-PQC-Test-CA",
        "-days",
        "1",
        "-extfile",
        ca_extensions.to_str().unwrap(),
        "-out",
        issuer.to_str().unwrap(),
    ]);
    openssl(&[
        "x509",
        "-in",
        issuer.to_str().unwrap(),
        "-outform",
        "DER",
        "-out",
        ca.to_str().unwrap(),
    ]);
    let extensions = root.join("extensions");
    std::fs::write(&extensions, b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost\n").unwrap();
    let module = Arc::new(Module::load(module_path).unwrap());
    let token = "pkcs11:token=tls-pqc-test".parse().unwrap();
    let parameters = [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ];
    let pin = SecretString::from("12345678");
    let mut session = module
        .open_owned_session(&token, SessionMode::ReadWrite)
        .unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, parameter) in parameters.into_iter().enumerate() {
        session
            .generate_ml_dsa_key_pair(parameter, &[0xA1, index as u8], b"TLS ML-DSA", index == 1)
            .unwrap();
        let public = PublicKeyRef::new(
            format!("pkcs11:token=tls-pqc-test;id=%A1%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let raw = session.ml_dsa_public_key(&public).unwrap();
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap(
                    [
                        "2.16.840.1.101.3.4.3.17",
                        "2.16.840.1.101.3.4.3.18",
                        "2.16.840.1.101.3.4.3.19",
                    ][index],
                ),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(raw.as_bytes()).unwrap(),
        }
        .to_der()
        .unwrap();
        let der = root.join(format!("{index}.spki.der"));
        let pem = root.join(format!("{index}.pem"));
        std::fs::write(&der, spki).unwrap();
        openssl(&[
            "pkey",
            "-pubin",
            "-inform",
            "DER",
            "-in",
            der.to_str().unwrap(),
            "-out",
            pem.to_str().unwrap(),
        ]);
        openssl(&[
            "x509",
            "-new",
            "-force_pubkey",
            pem.to_str().unwrap(),
            "-CA",
            issuer.to_str().unwrap(),
            "-CAkey",
            issuer_key.to_str().unwrap(),
            "-set_serial",
            &(index + 1).to_string(),
            "-subj",
            "/CN=localhost",
            "-days",
            "1",
            "-extfile",
            extensions.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            root.join(format!("{index}.der")).to_str().unwrap(),
        ]);
    }
    session.close().unwrap();
    std::fs::remove_file(issuer_key).unwrap();
    let pool = Arc::new(
        SessionPool::new_owned(
            module.clone(),
            &token,
            SessionMode::ReadOnly,
            NonZeroUsize::new(1).unwrap(),
        )
        .unwrap(),
    );
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let hybrid = pkcs11_rustls_adapter::hybrid_tls13_provider(&provider).unwrap();
    for (index, parameter) in parameters.into_iter().enumerate() {
        let chain = vec![
            certificate(&root.join(format!("{index}.der"))),
            certificate(&ca),
        ];
        let calls = Arc::new(AtomicUsize::new(0));
        let source = source(index == 1, calls.clone());
        for (policy, provider, expected) in [
            (
                MlDsaSigningPolicy::default(),
                Arc::new(rustls::crypto::ring::default_provider()),
                "scheme",
            ),
            (
                MlDsaSigningPolicy {
                    parameter_sets: vec![],
                },
                provider.clone(),
                "policy",
            ),
        ] {
            let error = Credential::load_ml_dsa(
                pool.clone(),
                key(index),
                chain.clone(),
                policy,
                source.clone(),
                provider,
            )
            .unwrap_err();
            assert!(match expected {
                "scheme" => matches!(error, Error::NoCompatibleScheme),
                _ => matches!(
                    error,
                    Error::Runtime(pkcs11_runtime::Error::UnsupportedSigning(_))
                ),
            });
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
        let credential = Arc::new(
            Credential::load_ml_dsa(
                pool.clone(),
                key(index),
                chain.clone(),
                MlDsaSigningPolicy::default(),
                source.clone(),
                provider.clone(),
            )
            .unwrap(),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let scheme = [
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ][index];
        let bundle = credential.certified_key();
        assert!(
            bundle
                .key
                .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_none()
        );
        assert!(
            bundle
                .key
                .choose_scheme(&[[
                    SignatureScheme::ML_DSA_65,
                    SignatureScheme::ML_DSA_44,
                    SignatureScheme::ML_DSA_44
                ][index]])
                .is_none()
        );
        let signer = bundle.key.choose_scheme(&[scheme]).unwrap();
        assert_eq!(signer.scheme(), scheme);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let (hybrid_client, hybrid_server) = configs(
            hybrid.clone(),
            credential.clone(),
            certificate(&ca),
            false,
            true,
            &rustls::version::TLS13,
        );
        let mut classical = (*provider).clone();
        classical.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        let (classical_client, classical_server) = configs(
            Arc::new(classical),
            credential.clone(),
            certificate(&ca),
            false,
            true,
            &rustls::version::TLS13,
        );
        let before = calls.load(Ordering::SeqCst);
        assert!(handshake((classical_client, hybrid_server), false, false).is_err());
        assert!(handshake((hybrid_client, classical_server), false, false).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), before);
        for mutual in [false, true] {
            let before = calls.load(Ordering::SeqCst);
            handshake(
                configs(
                    hybrid.clone(),
                    credential.clone(),
                    certificate(&ca),
                    mutual,
                    true,
                    &rustls::version::TLS13,
                ),
                mutual,
                true,
            )
            .unwrap();
            assert_eq!(
                calls.load(Ordering::SeqCst) - before,
                if mutual { 2 } else { 1 }
            );
        }
        if index == 0 {
            // An unauthenticated classical peer must not poison later key-share hints.
            let mut preferred = (*provider).clone();
            preferred.kx_groups = vec![
                rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
                rustls::crypto::aws_lc_rs::kx_group::X25519,
            ];
            let preferred = Arc::new(preferred);
            let cache = Arc::new(ClientSessionMemoryCache::new(4));
            let name = ServerName::try_from("localhost").unwrap();
            let (mut untrusted, _) = configs(
                preferred.clone(),
                credential.clone(),
                certificate(&ca),
                false,
                false,
                &rustls::version::TLS13,
            );
            Arc::make_mut(&mut untrusted).resumption = Resumption::store(cache.clone());
            let mut classical = (*provider).clone();
            classical.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
            let (_, server) = configs(
                Arc::new(classical),
                credential.clone(),
                certificate(&ca),
                false,
                true,
                &rustls::version::TLS13,
            );
            assert!(matches!(
                handshake((untrusted, server), false, false),
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                ))
            ));
            assert_eq!(cache.kx_hint(&name), None);

            let (mut trusted, server) = configs(
                preferred.clone(),
                credential.clone(),
                certificate(&ca),
                false,
                true,
                &rustls::version::TLS13,
            );
            Arc::make_mut(&mut trusted).resumption = Resumption::store(cache.clone());
            handshake((trusted, server), false, true).unwrap();
            assert_eq!(cache.kx_hint(&name), Some(NamedGroup::X25519MLKEM768));
        }
        assert!(
            handshake(
                configs(
                    provider.clone(),
                    credential.clone(),
                    certificate(&ca),
                    false,
                    false,
                    &rustls::version::TLS13
                ),
                false,
                false
            )
            .is_err()
        );
        let before = calls.load(Ordering::SeqCst);
        assert!(
            handshake(
                configs(
                    provider.clone(),
                    credential.clone(),
                    certificate(&ca),
                    false,
                    true,
                    &rustls::version::TLS12
                ),
                false,
                false
            )
            .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), before);
        let held = pool.try_acquire(Authentication::None).unwrap();
        let before = calls.load(Ordering::SeqCst);
        assert!(signer.sign(b"exhausted").is_err());
        assert_eq!(calls.load(Ordering::SeqCst), before + 1);
        drop(held);
        assert_eq!(
            signer.sign(b"recovered").unwrap().len(),
            parameter.signature_length()
        );
        if index == 0 {
            let wrong = certificate(
                &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../pkcs11-client/tests/fixtures/mldsa44.der"),
            );
            assert!(matches!(
                Credential::load_ml_dsa(
                    pool.clone(),
                    key(index),
                    vec![wrong],
                    MlDsaSigningPolicy::default(),
                    source.clone(),
                    provider.clone()
                ),
                Err(Error::KeyCertificateMismatch)
            ));
            let mut mutation = module
                .open_owned_session(&token, SessionMode::ReadWrite)
                .unwrap();
            mutation
                .authenticate(Authentication::User(Pin::Value(&pin)))
                .unwrap();
            mutation
                .resolve(key(index).as_object_ref())
                .unwrap()
                .destroy()
                .unwrap();
            let public = PublicKeyRef::new(
                "pkcs11:token=tls-pqc-test;id=%A1%00;type=public"
                    .parse()
                    .unwrap(),
            )
            .unwrap();
            mutation
                .resolve(public.as_object_ref())
                .unwrap()
                .destroy()
                .unwrap();
            mutation
                .generate_ml_dsa_key_pair(parameter, &[0xA1, 0], b"replacement", false)
                .unwrap();
            let before = calls.load(Ordering::SeqCst);
            assert!(
                matches!(signer.sign(b"replacement"), Err(rustls::Error::General(message))
                if message == Error::KeyCertificateMismatch.to_string())
            );
            assert_eq!(calls.load(Ordering::SeqCst), before + 1);
            mutation.close().unwrap();
        }
    }
    Arc::try_unwrap(pool)
        .unwrap_or_else(|_| panic!("credentials retained the pool"))
        .close()
        .unwrap();
    Arc::try_unwrap(module).unwrap().finalize().unwrap();
}
