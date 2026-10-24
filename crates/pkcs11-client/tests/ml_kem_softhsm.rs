// SPDX-License-Identifier: MIT OR Apache-2.0
//! Handle-free ML-KEM workflows using persistent nonextractable token secrets.
use pkcs11_client::{
    Attribute, AttributeType, Authentication, Error, ErrorKind, MlKemOperation, MlKemParameterSet,
    MlKemPublicKey, MlKemRequest, ObjectClass, Pin, PrivateKeyRef, Provider, PublicKeyRef,
    SessionMode, object_reference,
};
use secrecy::SecretString;

#[test]
#[ignore = "requires PKCS11_TEST_REQUIRE_PQC=1 tools/test-softhsm.sh"]
fn client_ml_kem_generation_and_shared_secret_lifecycle() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    assert_eq!(std::env::var("PKCS11_TEST_REQUIRE_PQC").as_deref(), Ok("1"));
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=pqc-test".parse().unwrap();
    let parameters = [
        MlKemParameterSet::MlKem512,
        MlKemParameterSet::MlKem768,
        MlKemParameterSet::MlKem1024,
    ];
    assert_eq!(
        provider.ml_kem_generation_options(&token).unwrap(),
        parameters
    );
    let pin = SecretString::from("12345678");
    let mut session = provider
        .management(
            &token,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    for (index, parameter) in parameters.into_iter().enumerate() {
        session
            .generate_ml_kem_key_pair(parameter, &[0xF1, index as u8], b"client ML-KEM")
            .unwrap();
        let public = PublicKeyRef::new(
            format!("pkcs11:token=pqc-test;id=%F1%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let private = PrivateKeyRef::new(
            format!("pkcs11:token=pqc-test;id=%F1%{index:02X};type=private")
                .parse()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            session
                .ml_kem_capabilities(public.as_object_ref(), MlKemOperation::Encapsulate)
                .unwrap()
                .parameter_set,
            parameter
        );
        assert_eq!(
            session
                .ml_kem_capabilities(private.as_object_ref(), MlKemOperation::Decapsulate)
                .unwrap()
                .parameter_set,
            parameter
        );
        assert_eq!(
            session
                .ml_kem_capabilities(public.as_object_ref(), MlKemOperation::Decapsulate)
                .unwrap_err()
                .kind(),
            ErrorKind::Policy
        );
        let sender = MlKemRequest {
            parameter_set: parameter,
            id: &[0xF2, index as u8, 1],
            label: b"client sender",
        };
        let receiver = MlKemRequest {
            id: &[0xF2, index as u8, 2],
            label: b"client receiver",
            ..sender
        };
        let wrong = MlKemRequest {
            parameter_set: parameters[(index + 1) % 3],
            ..sender
        };
        assert_eq!(
            session
                .encapsulate_ml_kem(&public, &wrong)
                .unwrap_err()
                .kind(),
            ErrorKind::Policy
        );
        let der = session.export_ml_kem_public_key(&public).unwrap();
        let peer = MlKemPublicKey::from_spki_der(&der).unwrap();
        assert_eq!(peer.parameter_set(), parameter);
        assert_eq!(peer.to_spki_der().unwrap(), der);
        // Independent decoder: OpenSSL must preserve the generated SPKI exactly.
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let mut process = Command::new(std::env::var_os("PKCS11_TEST_PQC_OPENSSL").unwrap())
            .args(["pkey", "-pubin", "-inform", "DER", "-outform", "DER"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        process.stdin.take().unwrap().write_all(&der).unwrap();
        let output = process.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, der);
        session
            .import_ml_kem_public_key(&peer, &[0xF3, index as u8], b"client peer")
            .unwrap();
        let imported = PublicKeyRef::new(
            format!("pkcs11:token=pqc-test;id=%F3%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(session.export_ml_kem_public_key(&imported).unwrap(), der);
        let ciphertext = session.encapsulate_ml_kem(&imported, &sender).unwrap();
        assert_eq!(ciphertext.len(), parameter.ciphertext_length());
        assert_eq!(
            session
                .encapsulate_ml_kem(&public, &sender)
                .unwrap_err()
                .kind(),
            ErrorKind::Input
        );
        assert_eq!(
            session
                .decapsulate_ml_kem(&private, &receiver, &ciphertext[..ciphertext.len() - 1])
                .unwrap_err()
                .kind(),
            ErrorKind::Input
        );
        session
            .decapsulate_ml_kem(&private, &receiver, &ciphertext)
            .unwrap();
        assert_eq!(
            session
                .decapsulate_ml_kem(&private, &receiver, &ciphertext)
                .unwrap_err()
                .kind(),
            ErrorKind::Input
        );
        for direction in 1..=2 {
            let reference = object_reference(
                format!("pkcs11:token=pqc-test;id=%F2%{index:02X}%{direction:02X};type=secret-key")
                    .parse()
                    .unwrap(),
            )
            .unwrap();
            let attrs = session
                .inspect(
                    &reference,
                    &[
                        AttributeType::Sensitive,
                        AttributeType::Extractable,
                        AttributeType::Derive,
                        AttributeType::Class,
                        AttributeType::ValueLen,
                    ],
                )
                .unwrap();
            for expected in [
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Derive(true),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::ValueLen(32.into()),
            ] {
                assert!(attrs.iter().any(|attr| {
                    attr.values
                        .as_ref()
                        .is_some_and(|values| values.expose_values().contains(&expected))
                }));
            }
            assert!(matches!(
                session.export_public(&reference),
                Err(Error::UnsupportedExport)
            ));
            assert!(matches!(
                session.export_value(&reference),
                Err(Error::UnsupportedExport)
            ));
            session.delete(&reference).unwrap();
            assert_eq!(
                session
                    .inspect(&reference, &[AttributeType::Class])
                    .unwrap_err()
                    .kind(),
                ErrorKind::Selection
            );
        }
        session.delete(imported.as_object_ref()).unwrap();
        session.delete(private.as_object_ref()).unwrap();
        session.delete(public.as_object_ref()).unwrap();
    }
    session.close().unwrap();
    let mut read_only = provider
        .management(
            &token,
            SessionMode::ReadOnly,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    assert_eq!(
        read_only
            .generate_ml_kem_key_pair(parameters[0], b"read-only", b"read-only")
            .unwrap_err()
            .kind(),
        ErrorKind::Policy
    );
    read_only.close().unwrap();
    provider.finalize().unwrap();
}
