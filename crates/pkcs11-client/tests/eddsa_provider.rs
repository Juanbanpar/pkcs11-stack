// SPDX-License-Identifier: MIT OR Apache-2.0
//! Run only with the disposable SoftHSM store created by tools/test-softhsm.sh.
use pkcs11_client::*;
use secrecy::SecretString;
use std::{num::NonZeroUsize, process::Command};

fn uri(label: &str, class: &str) -> Pkcs11Uri {
    format!("pkcs11:token=client-test;object={label};type={class}")
        .parse()
        .unwrap()
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable token"]
fn pure_eddsa_generation_import_signatures_binding_and_context_authentication() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=client-test".parse().unwrap();
    let choices = provider.eddsa_generation_options(&token).unwrap();
    if std::env::var("PKCS11_TEST_REQUIRE_EDDSA").as_deref() == Ok("1") {
        assert_eq!(choices, [EdDsaCurve::Ed25519, EdDsaCurve::Ed448]);
    }
    let pin = SecretString::from("12345678");
    let auth = || Authentication::User(Pin::Value(&pin));
    let scratch = std::path::PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    if !choices.is_empty() {
        let output = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=EdDSA-fixture-CA",
                "-days",
                "1",
                "-keyout",
            ])
            .arg(scratch.join("eddsa-ca.key"))
            .args(["-out"])
            .arg(scratch.join("eddsa-ca.pem"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for curve in choices {
        for always in [false, true] {
            let label = format!("client-{curve:?}-{always}");
            let public = PublicKeyRef::new(uri(&label, "public")).unwrap();
            let private = PrivateKeyRef::new(uri(&label, "private")).unwrap();
            let mut session = provider
                .management(&token, SessionMode::ReadWrite, auth())
                .unwrap();
            session
                .generate_eddsa_key_pair(curve, label.as_bytes(), label.as_bytes(), always)
                .unwrap();
            assert!(
                session
                    .generate_eddsa_key_pair(curve, label.as_bytes(), label.as_bytes(), always)
                    .is_err()
            );
            assert!(
                session
                    .eddsa_capabilities(private.as_object_ref())
                    .unwrap()
                    .can_sign
            );
            let caps = session.eddsa_capabilities(public.as_object_ref()).unwrap();
            assert!(caps.can_verify && !caps.can_sign && !caps.always_authenticate);
            let attributes = session
                .inspect(
                    private.as_object_ref(),
                    &[
                        AttributeType::Sensitive,
                        AttributeType::Extractable,
                        AttributeType::Derive,
                        AttributeType::AllowedMechanisms,
                    ],
                )
                .unwrap();
            let values: Vec<_> = attributes
                .iter()
                .flat_map(|read| read.values.as_ref().unwrap().expose_values())
                .collect();
            assert!(values.contains(&&Attribute::Sensitive(true)));
            assert!(values.contains(&&Attribute::Extractable(false)));
            assert!(values.contains(&&Attribute::Derive(false)));
            assert!(values.contains(&&Attribute::AllowedMechanisms(vec![MechanismType::EDDSA])));
            let der = session.export_eddsa_public_key(&public).unwrap();
            let verifier = EdDsaVerifyingKey::from_spki_der(&der).unwrap();
            assert_eq!(verifier.curve(), curve);
            let imported_label = format!("import-{label}");
            session
                .import_eddsa_public_key(
                    &verifier,
                    imported_label.as_bytes(),
                    imported_label.as_bytes(),
                )
                .unwrap();
            assert!(
                session
                    .import_eddsa_public_key(
                        &verifier,
                        imported_label.as_bytes(),
                        imported_label.as_bytes()
                    )
                    .is_err()
            );
            let imported = PublicKeyRef::new(uri(&imported_label, "public")).unwrap();
            assert_eq!(
                session.export_public(imported.as_object_ref()).unwrap(),
                der
            );
            let params = EdDsaRequest {
                curve,
                message: b"EdDSA original-message interoperability",
            };
            if always {
                assert!(session.sign_eddsa(&private, &params, None).is_err());
            }
            let wrong = EdDsaRequest {
                curve: if curve == EdDsaCurve::Ed25519 {
                    EdDsaCurve::Ed448
                } else {
                    EdDsaCurve::Ed25519
                },
                ..params
            };
            assert!(session.sign_eddsa(&private, &wrong, None).is_err());
            for message in [params.message, b""] {
                let request = EdDsaRequest { message, ..params };
                let signature = session
                    .sign_eddsa(&private, &request, always.then_some(Pin::Value(&pin)))
                    .unwrap();
                verifier.verify_signature(&request, &signature).unwrap();
                session.verify_eddsa(&public, &request, &signature).unwrap();
                session
                    .verify_eddsa(&imported, &request, &signature)
                    .unwrap();
                assert!(matches!(
                    session.verify_eddsa(&public, &request, &vec![0; signature.len()]),
                    Err(Error::SignatureMismatch)
                ));
                session.verify_eddsa(&public, &request, &signature).unwrap();
            }
            let signature = session
                .sign_eddsa(&private, &params, always.then_some(Pin::Value(&pin)))
                .unwrap();
            session.close().unwrap();
            let spki = scratch.join(format!("{label}.spki"));
            std::fs::write(&spki, &der).unwrap();
            let cert = scratch.join(format!("{label}.cert"));
            let output = Command::new("openssl")
                .args(["x509", "-new", "-force_pubkey"])
                .arg(&spki)
                .args(["-CA"])
                .arg(scratch.join("eddsa-ca.pem"))
                .args(["-CAkey"])
                .arg(scratch.join("eddsa-ca.key"))
                .args([
                    "-set_serial",
                    "991",
                    "-subj",
                    "/CN=EdDSA",
                    "-days",
                    "1",
                    "-outform",
                    "DER",
                    "-out",
                ])
                .arg(&cert)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let certificate = EdDsaCertificate::from_der(std::fs::read(cert).unwrap()).unwrap();
            certificate.verify_signature(&params, &signature).unwrap();
            let client = provider
                .client(
                    &token,
                    NonZeroUsize::new(1).unwrap(),
                    SigningPolicy::default(),
                )
                .unwrap();
            let bad_pin = SecretString::from("incorrect");
            assert!(matches!(
                client.verify_eddsa(
                    &public,
                    &params,
                    &[],
                    Authentication::User(Pin::Value(&bad_pin))
                ),
                Err(Error::SignatureMismatch)
            ));
            let identity = client
                .bind_eddsa_identity(
                    private,
                    certificate,
                    auth(),
                    always.then_some(Pin::Value(&pin)),
                )
                .unwrap();
            let signature = client
                .sign_eddsa_identity(
                    &identity,
                    &params,
                    auth(),
                    always.then_some(Pin::Value(&pin)),
                )
                .unwrap();
            verifier.verify_signature(&params, &signature).unwrap();
            let name = match curve {
                EdDsaCurve::Ed25519 => "ed25519",
                EdDsaCurve::Ed448 => "ed448",
            };
            let wrong_certificate = EdDsaCertificate::from_der(
                std::fs::read(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join(format!("tests/fixtures/eddsa/{name}.der")),
                )
                .unwrap(),
            )
            .unwrap();
            assert!(matches!(
                client.bind_eddsa_identity(
                    PrivateKeyRef::new(uri(&label, "private")).unwrap(),
                    wrong_certificate,
                    auth(),
                    always.then_some(Pin::Value(&pin))
                ),
                Err(Error::KeyCertificateMismatch)
            ));
            client
                .sign_eddsa_identity(
                    &identity,
                    &params,
                    auth(),
                    always.then_some(Pin::Value(&pin)),
                )
                .unwrap();
            // The live pool already holds the token-wide USER login.
            let mut replacement = provider
                .management(&token, SessionMode::ReadWrite, Authentication::None)
                .unwrap();
            replacement.delete(public.as_object_ref()).unwrap();
            replacement.delete(identity.key().as_object_ref()).unwrap();
            replacement
                .generate_eddsa_key_pair(curve, label.as_bytes(), label.as_bytes(), always)
                .unwrap();
            replacement.close().unwrap();
            assert!(matches!(
                client.sign_eddsa_identity(
                    &identity,
                    &params,
                    auth(),
                    always.then_some(Pin::Value(&pin))
                ),
                Err(Error::KeyCertificateMismatch)
            ));
            client.close().unwrap();
        }
    }
    provider.finalize().unwrap();
}
