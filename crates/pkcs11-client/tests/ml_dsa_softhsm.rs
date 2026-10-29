// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed ML-DSA client workflows and OpenSSL interoperability.
use pkcs11_client::{
    Authentication, Error, ErrorKind, MlDsaCertificate, MlDsaHedging, MlDsaParameterSet,
    MlDsaParameters, MlDsaRequest, MlDsaSigningPolicy, MlDsaVerifyingKey, Pin, PrivateKeyRef,
    Provider, PublicKeyRef, SessionMode, SigningPolicy,
};
use secrecy::SecretString;
use std::{num::NonZeroUsize, path::PathBuf, process::Command};

fn openssl(args: &[&str]) {
    let binary = std::env::var_os("PKCS11_TEST_PQC_OPENSSL").unwrap();
    let output = Command::new(binary).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "OpenSSL command failed: {}",
        output.status
    );
}

#[test]
#[ignore = "requires tools/test-ml-dsa.sh"]
fn client_ml_dsa_signing_binding_and_public_export() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let token = "pkcs11:token=pqc-test".parse().unwrap();
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let parameters = [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ];
    assert_eq!(
        provider.ml_dsa_generation_options(&token).unwrap(),
        parameters
    );
    let pin = SecretString::from("12345678");
    let auth = || Authentication::User(Pin::Value(&pin));
    let issuer_key = root.join("mldsa-issuer.key");
    let issuer_cert = root.join("mldsa-issuer.pem");
    openssl(&[
        "genpkey",
        "-algorithm",
        "ED25519",
        "-out",
        issuer_key.to_str().unwrap(),
    ]);
    openssl(&[
        "x509",
        "-new",
        "-key",
        issuer_key.to_str().unwrap(),
        "-subj",
        "/CN=ML-DSA-Test-CA",
        "-days",
        "1",
        "-out",
        issuer_cert.to_str().unwrap(),
    ]);
    let mut management = provider
        .management(&token, SessionMode::ReadWrite, auth())
        .unwrap();
    for (index, parameter) in parameters.into_iter().enumerate() {
        management
            .generate_ml_dsa_key_pair(
                parameter,
                &[0xC1, index as u8],
                b"client ML-DSA",
                index == 1,
            )
            .unwrap();
        let key = PublicKeyRef::new(
            format!("pkcs11:token=pqc-test;id=%C1%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let der = management.export_ml_dsa_public_key(&key).unwrap();
        assert_eq!(management.export_public(key.as_object_ref()).unwrap(), der);
        assert!(management.export_classical_public_key(&key).is_err());
        let private = pkcs11_client::object_reference(
            format!("pkcs11:token=pqc-test;id=%C1%{index:02X};type=private")
                .parse()
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            management.export_public(&private),
            Err(Error::UnsupportedExport)
        ));
        let der_path = root.join(format!("mldsa-{index}.der"));
        let pem_path = root.join(format!("mldsa-{index}.pem"));
        let cert_path = root.join(format!("mldsa-{index}.cert.der"));
        std::fs::write(&der_path, der).unwrap();
        openssl(&[
            "pkey",
            "-pubin",
            "-inform",
            "DER",
            "-in",
            der_path.to_str().unwrap(),
            "-out",
            pem_path.to_str().unwrap(),
        ]);
        openssl(&[
            "x509",
            "-new",
            "-force_pubkey",
            pem_path.to_str().unwrap(),
            "-CA",
            issuer_cert.to_str().unwrap(),
            "-CAkey",
            issuer_key.to_str().unwrap(),
            "-set_serial",
            &(index + 1).to_string(),
            "-subj",
            "/CN=ML-DSA-Binding",
            "-days",
            "1",
            "-outform",
            "DER",
            "-out",
            cert_path.to_str().unwrap(),
        ]);
        let certificate = MlDsaCertificate::from_der(std::fs::read(cert_path).unwrap()).unwrap();
        management
            .import_certificate(
                certificate.document(),
                &[0xC2, index as u8],
                b"ML-DSA certificate",
            )
            .unwrap();
    }
    std::fs::remove_file(&issuer_key).unwrap();
    management.close().unwrap();
    let client = provider
        .client(
            &token,
            NonZeroUsize::new(1).unwrap(),
            SigningPolicy::default(),
        )
        .unwrap();
    for (index, parameter) in parameters.into_iter().enumerate() {
        let key = client
            .private_key(
                format!("pkcs11:token=pqc-test;id=%C1%{index:02X};type=private")
                    .parse()
                    .unwrap(),
                auth(),
            )
            .unwrap();
        let public = client
            .public_key(
                format!("pkcs11:token=pqc-test;id=%C1%{index:02X};type=public")
                    .parse()
                    .unwrap(),
                auth(),
            )
            .unwrap();
        assert_eq!(
            client
                .ml_dsa_capabilities(&key, auth())
                .unwrap()
                .parameter_set,
            parameter
        );
        let der_path = root.join(format!("mldsa-{index}.der"));
        let der = client.export_ml_dsa_public_key(&public, auth()).unwrap();
        assert_eq!(std::fs::read(&der_path).unwrap(), der);
        openssl(&[
            "pkey",
            "-pubin",
            "-inform",
            "DER",
            "-in",
            der_path.to_str().unwrap(),
            "-noout",
        ]);
        let policy = MlDsaSigningPolicy::default();
        let request = MlDsaRequest {
            parameter_set: parameter,
            message: b"client ML-DSA message\n",
            context: b"client-context",
            hedging: MlDsaHedging::Required,
        };
        let context_pin = || (index == 1).then_some(Pin::Value(&pin));
        let verifier = MlDsaVerifyingKey::from_spki_der(&der).unwrap();
        let certificate_uri = format!("pkcs11:token=pqc-test;id=%C2%{index:02X};type=cert");
        let certificate = client
            .ml_dsa_certificate(certificate_uri.parse().unwrap(), auth())
            .unwrap();
        assert_eq!(certificate.spki_der(), der);
        let held = client.pool().try_acquire(auth()).unwrap();
        assert_eq!(
            client
                .bind_ml_dsa_identity(
                    PrivateKeyRef::new(key.as_object_ref().uri().to_string().parse().unwrap())
                        .unwrap(),
                    certificate,
                    &MlDsaSigningPolicy {
                        parameter_sets: vec![]
                    },
                    auth(),
                    context_pin()
                )
                .unwrap_err()
                .kind(),
            ErrorKind::Policy
        );
        drop(held);
        let wrong = MlDsaCertificate::from_der(
            std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures")
                    .join(format!("mldsa{}.der", [44, 65, 87][index])),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            client.bind_ml_dsa_identity(
                PrivateKeyRef::new(key.as_object_ref().uri().to_string().parse().unwrap()).unwrap(),
                wrong,
                &policy,
                auth(),
                context_pin()
            ),
            Err(Error::KeyCertificateMismatch)
        ));
        let certificate = client
            .ml_dsa_certificate(certificate_uri.parse().unwrap(), auth())
            .unwrap();
        let identity = client
            .bind_ml_dsa_identity(
                PrivateKeyRef::new(key.as_object_ref().uri().to_string().parse().unwrap()).unwrap(),
                certificate,
                &policy,
                auth(),
                context_pin(),
            )
            .unwrap();
        let held = client.pool().try_acquire(auth()).unwrap();
        assert!(matches!(
            client.sign_ml_dsa_identity(
                &identity,
                &MlDsaRequest {
                    parameter_set: parameters[(index + 1) % 3],
                    ..request
                },
                &policy,
                auth(),
                context_pin()
            ),
            Err(Error::UnsupportedVerification)
        ));
        drop(held);
        let held = client.pool().try_acquire(auth()).unwrap();
        let denied = client
            .sign_ml_dsa(
                &key,
                &request,
                &MlDsaSigningPolicy {
                    parameter_sets: vec![],
                },
                auth(),
                context_pin(),
            )
            .unwrap_err();
        assert_eq!(denied.kind(), ErrorKind::Policy);
        let invalid = client
            .sign_ml_dsa(
                &key,
                &MlDsaRequest {
                    context: &[0; 256],
                    ..request
                },
                &policy,
                auth(),
                context_pin(),
            )
            .unwrap_err();
        assert_eq!(invalid.kind(), ErrorKind::Input);
        let exhausted = client
            .sign_ml_dsa(&key, &request, &policy, auth(), context_pin())
            .unwrap_err();
        assert_eq!(exhausted.kind(), ErrorKind::Runtime);
        drop(held);
        let signature = client
            .sign_ml_dsa_identity(&identity, &request, &policy, auth(), context_pin())
            .unwrap();
        identity
            .certificate()
            .verify_signature(&request, &signature)
            .unwrap();
        verifier.verify_signature(&request, &signature).unwrap();
        let stream_parameters = MlDsaParameters {
            parameter_set: parameter,
            context: request.context,
            hedging: request.hedging,
        };
        let streamed = client
            .sign_ml_dsa_identity_reader(
                &identity,
                stream_parameters,
                &policy,
                auth(),
                context_pin(),
                &mut &request.message[..],
            )
            .unwrap();
        verifier
            .verify_reader(stream_parameters, &mut &request.message[..], &streamed)
            .unwrap();
        for context in [b"".as_slice(), &[0xA5; 255]] {
            let edge = MlDsaRequest {
                context,
                message: b"",
                ..request
            };
            let signature = client
                .sign_ml_dsa_identity(&identity, &edge, &policy, auth(), context_pin())
                .unwrap();
            verifier.verify_signature(&edge, &signature).unwrap();
            let parameters = MlDsaParameters {
                parameter_set: parameter,
                context,
                hedging: edge.hedging,
            };
            let signature = client
                .sign_ml_dsa_identity_reader(
                    &identity,
                    parameters,
                    &policy,
                    auth(),
                    context_pin(),
                    &mut &b""[..],
                )
                .unwrap();
            verifier
                .verify_reader(parameters, &mut &b""[..], &signature)
                .unwrap();
        }
        client
            .verify_ml_dsa(&public, &request, &signature, auth())
            .unwrap();
        let mismatch = client
            .verify_ml_dsa(
                &public,
                &MlDsaRequest {
                    message: b"changed",
                    ..request
                },
                &signature,
                auth(),
            )
            .unwrap_err();
        assert!(matches!(mismatch, Error::SignatureMismatch));
        assert_eq!(mismatch.kind(), ErrorKind::Client);
        client
            .verify_ml_dsa(&public, &request, &signature, auth())
            .unwrap();
        // Streaming uses the same key/context and is independently verified by
        // RustCrypto and OpenSSL; token verification remains explicitly single-part.
        // The client's open pool already holds token-wide USER authentication.
        let mut streaming = provider
            .management(&token, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        assert_eq!(
            streaming.state().unwrap(),
            pkcs11_client::SessionState::RoUser
        );
        assert!(
            streaming
                .ml_dsa_streaming_capabilities(&key)
                .unwrap()
                .can_sign
        );
        for hedging in [
            MlDsaHedging::Required,
            MlDsaHedging::Preferred,
            MlDsaHedging::Deterministic,
        ] {
            for context in [b"".as_slice(), &[0xA5; 255]] {
                for message in [&[][..], request.message] {
                    let parameters = MlDsaParameters {
                        parameter_set: parameter,
                        context,
                        hedging,
                    };
                    let streamed = streaming
                        .sign_ml_dsa_reader(
                            &key,
                            parameters,
                            &policy,
                            context_pin(),
                            &mut std::io::Cursor::new(message),
                        )
                        .unwrap();
                    let expected = parameters.request(message);
                    verifier.verify_signature(&expected, &streamed).unwrap();
                    streaming
                        .verify_ml_dsa(&public, &expected, &streamed)
                        .unwrap();
                    if hedging == MlDsaHedging::Deterministic {
                        assert_eq!(
                            streamed,
                            streaming
                                .sign_ml_dsa(&key, &expected, &policy, context_pin())
                                .unwrap()
                        );
                    }
                }
            }
        }
        let parameters = MlDsaParameters {
            parameter_set: parameter,
            context: request.context,
            hedging: MlDsaHedging::Required,
        };
        let streamed = streaming
            .sign_ml_dsa_reader(
                &key,
                parameters,
                &policy,
                context_pin(),
                &mut std::io::Cursor::new(request.message),
            )
            .unwrap();
        let stream_input = root.join(format!("mldsa-stream-{index}.message"));
        let stream_sig = root.join(format!("mldsa-stream-{index}.sig"));
        std::fs::write(&stream_input, request.message).unwrap();
        std::fs::write(&stream_sig, &streamed).unwrap();
        openssl(&[
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            der_path.to_str().unwrap(),
            "-keyform",
            "DER",
            "-in",
            stream_input.to_str().unwrap(),
            "-sigfile",
            stream_sig.to_str().unwrap(),
            "-pkeyopt",
            "context-string:client-context",
        ]);
        if index == 0 {
            use std::io::{Read, copy};
            struct Chunks<R> {
                reader: R,
                maximum_buffer: usize,
                interrupted: bool,
            }
            impl<R: Read> Read for Chunks<R> {
                fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                    self.maximum_buffer = self.maximum_buffer.max(output.len());
                    if !self.interrupted {
                        self.interrupted = true;
                        return Err(std::io::ErrorKind::Interrupted.into());
                    }
                    let length = output.len().min(3071);
                    self.reader.read(&mut output[..length])
                }
            }
            // SoftHSM formats the entire accumulated message on every update,
            // even with log.level=ERROR. Keep this provider check practical;
            // the fixture separately checks bounded reader buffers and failures.
            let length = 256 * 1024 + 3;
            copy(
                &mut std::io::repeat(0xA5).take(length),
                &mut std::fs::File::create(&stream_input).unwrap(),
            )
            .unwrap();
            let mut reader = Chunks {
                reader: std::fs::File::open(&stream_input).unwrap(),
                maximum_buffer: 0,
                interrupted: false,
            };
            let signature = streaming
                .sign_ml_dsa_reader(&key, parameters, &policy, context_pin(), &mut reader)
                .unwrap();
            assert_eq!(reader.maximum_buffer, 64 * 1024);
            std::fs::write(&stream_sig, &signature).unwrap();
            openssl(&[
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                der_path.to_str().unwrap(),
                "-keyform",
                "DER",
                "-in",
                stream_input.to_str().unwrap(),
                "-sigfile",
                stream_sig.to_str().unwrap(),
                "-pkeyopt",
                "context-string:client-context",
            ]);
        }
        streaming.close().unwrap();
        let input = root.join(format!("mldsa-{index}.message"));
        let sig_path = root.join(format!("mldsa-{index}.sig"));
        std::fs::write(&input, request.message).unwrap();
        std::fs::write(&sig_path, &signature).unwrap();
        openssl(&[
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            der_path.to_str().unwrap(),
            "-keyform",
            "DER",
            "-in",
            input.to_str().unwrap(),
            "-sigfile",
            sig_path.to_str().unwrap(),
            "-pkeyopt",
            "context-string:client-context",
        ]);
    }
    // A reused locator must not preserve the old parameter set or cached handles.
    let private_uri = "pkcs11:token=pqc-test;id=%C1%00;type=private";
    let public_uri = "pkcs11:token=pqc-test;id=%C1%00;type=public";
    let old_key = client
        .private_key(private_uri.parse().unwrap(), auth())
        .unwrap();
    let original = client
        .ml_dsa_certificate(
            "pkcs11:token=pqc-test;id=%C2%00;type=cert".parse().unwrap(),
            auth(),
        )
        .unwrap();
    let original_identity = client
        .bind_ml_dsa_identity(
            PrivateKeyRef::new(private_uri.parse().unwrap()).unwrap(),
            original,
            &MlDsaSigningPolicy::default(),
            auth(),
            None,
        )
        .unwrap();
    let mut management = provider
        .management(&token, SessionMode::ReadWrite, Authentication::None)
        .unwrap();
    management
        .delete(&pkcs11_client::object_reference(private_uri.parse().unwrap()).unwrap())
        .unwrap();
    management
        .delete(&pkcs11_client::object_reference(public_uri.parse().unwrap()).unwrap())
        .unwrap();
    management
        .generate_ml_dsa_key_pair(parameters[1], &[0xC1, 0], b"replacement", false)
        .unwrap();
    let stale_request = MlDsaRequest {
        parameter_set: parameters[0],
        message: b"stale request",
        context: b"",
        hedging: MlDsaHedging::Required,
    };
    assert_eq!(
        client
            .sign_ml_dsa(
                &old_key,
                &stale_request,
                &MlDsaSigningPolicy::default(),
                auth(),
                None
            )
            .unwrap_err()
            .kind(),
        ErrorKind::Policy
    );
    assert_eq!(
        client
            .ml_dsa_capabilities(&old_key, auth())
            .unwrap()
            .parameter_set,
        parameters[1]
    );
    management
        .delete(&pkcs11_client::object_reference(private_uri.parse().unwrap()).unwrap())
        .unwrap();
    management
        .delete(&pkcs11_client::object_reference(public_uri.parse().unwrap()).unwrap())
        .unwrap();
    management
        .generate_ml_dsa_key_pair(parameters[0], &[0xC1, 0], b"replacement", false)
        .unwrap();
    assert!(matches!(
        client.sign_ml_dsa_identity(
            &original_identity,
            &stale_request,
            &MlDsaSigningPolicy::default(),
            auth(),
            None
        ),
        Err(Error::KeyCertificateMismatch)
    ));
    assert!(matches!(
        client.sign_ml_dsa_identity_reader(
            &original_identity,
            MlDsaParameters {
                parameter_set: stale_request.parameter_set,
                context: stale_request.context,
                hedging: stale_request.hedging
            },
            &MlDsaSigningPolicy::default(),
            auth(),
            None,
            &mut &stale_request.message[..]
        ),
        Err(Error::KeyCertificateMismatch)
    ));
    management.close().unwrap();
    client.close().unwrap();
    let mut management = provider
        .management(&token, SessionMode::ReadWrite, auth())
        .unwrap();
    let key = PrivateKeyRef::new(
        "pkcs11:token=pqc-test;id=%C1%00;type=private"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let public = PublicKeyRef::new(
        "pkcs11:token=pqc-test;id=%C1%00;type=public"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let request = MlDsaRequest {
        parameter_set: parameters[0],
        message: b"scoped session",
        context: b"",
        hedging: MlDsaHedging::Preferred,
    };
    assert!(management.ml_dsa_capabilities(&key).unwrap().can_sign);
    let signature = management
        .sign_ml_dsa(&key, &request, &MlDsaSigningPolicy::default(), None)
        .unwrap();
    management
        .verify_ml_dsa(&public, &request, &signature)
        .unwrap();
    assert!(matches!(
        management.verify_ml_dsa(&public, &request, &[]),
        Err(Error::SignatureMismatch)
    ));
    management.close().unwrap();
    provider.finalize().unwrap();
}
