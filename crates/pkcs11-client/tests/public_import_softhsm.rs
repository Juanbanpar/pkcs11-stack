// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public import permissions, independent signature checks and same-ID private keys.
use pkcs11_client::{
    Attribute, AttributeType, Authentication, Certificate, ClassicalPublicKey,
    ClassicalPublicKeyPurpose as Purpose, DecryptRequest, DigestAlgorithm, EncryptRequest, Error,
    HashingPolicy, KeyKind, ObjectRef, Pin, PrivateKeyRef, Provider, PublicKeyImportRequest,
    PublicKeyRef, RsaCipherOperation, RsaEncryptionKeyPairRequest, SessionMode, SignInput,
    SigningPolicy, VerifyRequest,
};
use secrecy::{ExposeSecret, SecretString};
use std::path::PathBuf;
fn reference(id: &[u8], kind: &str) -> ObjectRef {
    let id: String = id.iter().map(|b| format!("%{b:02X}")).collect();
    ObjectRef::new(
        format!("pkcs11:token=client-test;id={id};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn public(id: &[u8]) -> PublicKeyRef {
    PublicKeyRef::new(reference(id, "public").uri().to_string().parse().unwrap()).unwrap()
}
fn private(id: &[u8]) -> PrivateKeyRef {
    PrivateKeyRef::new(reference(id, "private").uri().to_string().parse().unwrap()).unwrap()
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable token"]
fn validated_public_import_permissions_verification_encryption_and_identity() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let provider = Provider::load_with_options(
        std::env::var_os("PKCS11_TEST_MODULE").unwrap(),
        pkcs11_client::ModuleOptions {
            interface: pkcs11_client::InterfaceSelection::Exact(
                pkcs11_client::InterfaceVersion::V2_40,
            ),
        },
    )
    .unwrap();
    let token = "pkcs11:token=client-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let mut session = provider
        .management(
            &token,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    let policy = SigningPolicy {
        hashing: HashingPolicy::SoftwareOnly,
        ..SigningPolicy::default()
    };
    for source in 1..=4u8 {
        let spki = std::fs::read(root.join(format!("{source:02X}-public.der"))).unwrap();
        let key = ClassicalPublicKey::from_spki_der(&spki).unwrap();
        let certificate = Certificate::from_der(
            std::fs::read(root.join(format!("{source:02X}-cert.der"))).unwrap(),
        )
        .unwrap();
        let id = [0xFA, source];
        let request = PublicKeyImportRequest {
            key: &key,
            purpose: Purpose::Verification,
            id: &id,
            label: b"imported verification key",
        };
        let mut ro = provider
            .management(&token, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        assert!(matches!(
            ro.import_classical_public_key(&request),
            Err(Error::Runtime(pkcs11_runtime::Error::ReadWriteRequired))
        ));
        ro.close().unwrap();
        session.import_classical_public_key(&request).unwrap();
        assert!(session.import_classical_public_key(&request).is_err());
        session.state().unwrap();
        assert_eq!(
            session.export_classical_public_key(&public(&id)).unwrap(),
            key.spki_der()
        );
        let attrs = session
            .inspect(
                &reference(&id, "public"),
                &[
                    AttributeType::Token,
                    AttributeType::Private,
                    AttributeType::Verify,
                    AttributeType::Encrypt,
                    AttributeType::VerifyRecover,
                    AttributeType::Wrap,
                    AttributeType::Derive,
                    AttributeType::Trusted,
                    AttributeType::Local,
                ],
            )
            .unwrap();
        for expected in [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            Attribute::Encrypt(false),
            Attribute::VerifyRecover(false),
            Attribute::Wrap(false),
            Attribute::Derive(false),
            Attribute::Trusted(false),
            Attribute::Local(false),
        ] {
            assert!(attrs.iter().any(|read| {
                read.values
                    .as_ref()
                    .is_some_and(|v| v.expose_values().contains(&expected))
            }));
        }
        let choices = session.verification_options(&public(&id), &policy).unwrap();
        assert_eq!(
            choices.len(),
            if matches!(key.key_kind(), KeyKind::Rsa { .. }) {
                6
            } else {
                3
            }
        );
        for choice in choices {
            let request = choice
                .parameters
                .request(SignInput::Message(b"public import interoperability"));
            let signature = session
                .sign(&private(&[source]), &request, &policy, None)
                .unwrap();
            certificate.verify_signature(&request, &signature).unwrap();
            session
                .verify_token(
                    &public(&id),
                    &VerifyRequest {
                        parameters: request,
                        signature: &signature,
                    },
                    &policy,
                )
                .unwrap();
            let mut bad = signature;
            let end = bad.len() - 1;
            bad[end] ^= 1;
            assert!(matches!(
                session.verify_token(
                    &public(&id),
                    &VerifyRequest {
                        parameters: choice
                            .parameters
                            .request(SignInput::Message(b"public import interoperability")),
                        signature: &bad
                    },
                    &policy
                ),
                Err(Error::SignatureMismatch)
            ));
            session.state().unwrap();
        }
        if matches!(key.key_kind(), KeyKind::Rsa { .. }) {
            assert!(
                session
                    .oaep_options(&reference(&id, "public"), RsaCipherOperation::Encrypt)
                    .is_err()
            );
        }
        session.delete(&reference(&id, "public")).unwrap();
    }
    // Reimporting a pair's public key with the same ID must leave its sensitive,
    // nonextractable private object unchanged and usable.
    let id = b"public-reimport-pair";
    session
        .generate_rsa_encryption_key_pair(&RsaEncryptionKeyPairRequest {
            bits: 2048,
            id,
            label: b"reimport pair",
            always_authenticate: false,
        })
        .unwrap();
    let key = ClassicalPublicKey::from_spki_der(
        &session.export_classical_public_key(&public(id)).unwrap(),
    )
    .unwrap();
    session.delete(&reference(id, "public")).unwrap();
    session
        .import_classical_public_key(&PublicKeyImportRequest {
            key: &key,
            purpose: Purpose::Encryption,
            id,
            label: b"reimported public",
        })
        .unwrap();
    assert!(
        session
            .verification_options(&public(id), &policy)
            .unwrap()
            .is_empty()
    );
    assert!(
        session
            .verify_token(
                &public(id),
                &VerifyRequest {
                    parameters: pkcs11_client::SignRequest {
                        algorithm: pkcs11_client::SignatureAlgorithm::RsaPkcs1,
                        digest: DigestAlgorithm::Sha256,
                        input: SignInput::Message(b"wrong purpose"),
                        pss: None
                    },
                    signature: &[0; 256],
                },
                &policy
            )
            .is_err()
    );
    session.state().unwrap();
    if std::env::var("PKCS11_TEST_REQUIRE_RSA_OAEP_SHA2").as_deref() == Ok("1") {
        for digest in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let ciphertext = session
                .encrypt(
                    &public(id),
                    &EncryptRequest {
                        digest,
                        plaintext: b"imported public encryption",
                    },
                )
                .unwrap();
            let plaintext = session
                .decrypt(
                    &private(id),
                    &DecryptRequest {
                        digest,
                        ciphertext: &ciphertext,
                    },
                )
                .unwrap();
            assert_eq!(plaintext.expose_secret(), b"imported public encryption");
        }
    }
    let attributes = session
        .inspect(
            &reference(id, "private"),
            &[
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::Decrypt,
                AttributeType::Sign,
            ],
        )
        .unwrap();
    for expected in [
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Decrypt(true),
        Attribute::Sign(false),
    ] {
        assert!(attributes.iter().any(|read| {
            read.values
                .as_ref()
                .is_some_and(|v| v.expose_values().contains(&expected))
        }));
    }
    session.delete(&reference(id, "public")).unwrap();
    session.delete(&reference(id, "private")).unwrap();
    session.close().unwrap();
    provider.finalize().unwrap();
}
