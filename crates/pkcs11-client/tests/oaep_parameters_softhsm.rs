// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent OAEP hash/MGF1/label interoperability through the 2.40 interface.
use pkcs11_client::*;
use secrecy::{ExposeSecret, SecretString};
use std::{path::Path, process::Command};

fn session<T>(
    provider: &Provider,
    run: impl FnOnce(&mut ManagementSession<'_>) -> Result<T, Error>,
) -> Result<T, Error> {
    let pin = SecretString::from("12345678");
    let mut session = provider
        .management(
            &"pkcs11:token=client-test".parse().unwrap(),
            SessionMode::ReadOnly,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    let result = run(&mut session);
    session.close().unwrap();
    result
}
fn openssl(root: &Path, encrypt: bool, digest: &str, mgf: &str, label: &[u8]) {
    let mut command = Command::new("openssl");
    command.arg("pkeyutl");
    if encrypt {
        command
            .args(["-encrypt", "-pubin", "-keyform", "DER", "-inkey"])
            .arg(root.join("cipher-public.der"));
    } else {
        command
            .args(["-decrypt", "-inkey"])
            .arg(root.join("cipher.key"));
    }
    command
        .arg("-in")
        .arg(root.join(if encrypt {
            "oaep-parameters-message"
        } else {
            "oaep-parameters-cipher"
        }))
        .arg("-out")
        .arg(root.join(if encrypt {
            "oaep-parameters-cipher"
        } else {
            "oaep-parameters-plain"
        }))
        .args([
            "-pkeyopt",
            "rsa_padding_mode:oaep",
            "-pkeyopt",
            &format!("rsa_oaep_md:{digest}"),
            "-pkeyopt",
            &format!("rsa_mgf1_md:{mgf}"),
        ]);
    if !label.is_empty() {
        let hex: String = label.iter().map(|byte| format!("{byte:02x}")).collect();
        command.args(["-pkeyopt", &format!("rsa_oaep_label:{hex}")]);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable token"]
fn explicit_oaep_digests_binary_labels_bounds_and_context_authentication() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    // The packaged provider may advertise OAEP while accepting only SHA-1.
    if std::env::var("PKCS11_TEST_REQUIRE_RSA_OAEP_SHA2").as_deref() != Ok("1") {
        return;
    }
    let root = std::path::PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let provider = Provider::load_with_options(
        std::env::var_os("PKCS11_TEST_MODULE").unwrap(),
        ModuleOptions {
            interface: InterfaceSelection::Exact(InterfaceVersion::V2_40),
        },
    )
    .unwrap();
    let public = PublicKeyRef::new(
        "pkcs11:token=client-test;id=%20;type=public"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let private = PrivateKeyRef::new(
        "pkcs11:token=client-test;id=%20;type=private"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let always = PrivateKeyRef::new(
        "pkcs11:token=client-test;id=%21;type=private"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let digests = [
        (DigestAlgorithm::Sha256, "sha256", 190),
        (DigestAlgorithm::Sha384, "sha384", 158),
        (DigestAlgorithm::Sha512, "sha512", 126),
    ];
    for (digest, name, maximum) in digests {
        for (mgf_digest, mgf, _) in digests {
            for label in [&[][..], b"\0binary\xfflabel".as_slice()] {
                let parameters = RsaOaepParameters {
                    digest,
                    mgf_digest,
                    label,
                };
                let message = vec![0xA5; maximum];
                std::fs::write(root.join("oaep-parameters-message"), &message).unwrap();
                let ciphertext = session(&provider, |s| {
                    s.encrypt_oaep(&public, &parameters, &message)
                })
                .unwrap();
                assert_eq!(ciphertext.len(), 256);
                std::fs::write(root.join("oaep-parameters-cipher"), ciphertext).unwrap();
                openssl(&root, false, name, mgf, label);
                assert_eq!(
                    std::fs::read(root.join("oaep-parameters-plain")).unwrap(),
                    message
                );
                openssl(&root, true, name, mgf, label);
                let ciphertext = std::fs::read(root.join("oaep-parameters-cipher")).unwrap();
                let recovered = session(&provider, |s| {
                    s.decrypt_oaep(&private, &parameters, &ciphertext, None)
                })
                .unwrap();
                assert_eq!(recovered.expose_secret(), &message);
                session(&provider, |s| {
                    assert!(
                        s.encrypt_oaep(&public, &parameters, &vec![0; maximum + 1])
                            .is_err()
                    );
                    s.state()?;
                    Ok(())
                })
                .unwrap();
            }
        }
    }
    let label = vec![0xFF; 4096];
    let parameters = RsaOaepParameters {
        digest: DigestAlgorithm::Sha256,
        mgf_digest: DigestAlgorithm::Sha512,
        label: &label,
    };
    let ciphertext = session(&provider, |s| s.encrypt_oaep(&public, &parameters, b"")).unwrap();
    assert!(
        session(&provider, |s| s.decrypt_oaep(
            &private,
            &parameters,
            &ciphertext,
            None
        ))
        .unwrap()
        .expose_secret()
        .is_empty()
    );
    for wrong in [
        RsaOaepParameters {
            label: b"wrong",
            ..parameters
        },
        RsaOaepParameters {
            mgf_digest: DigestAlgorithm::Sha384,
            ..parameters
        },
    ] {
        assert!(
            session(&provider, |s| s.decrypt_oaep(
                &private,
                &wrong,
                &ciphertext,
                None
            ))
            .is_err()
        );
    }
    let pin = SecretString::from("12345678");
    assert!(
        session(&provider, |s| s.decrypt_oaep(
            &always,
            &parameters,
            &ciphertext,
            Some(Pin::Value(&pin))
        ))
        .unwrap()
        .expose_secret()
        .is_empty()
    );
    assert!(matches!(
        session(&provider, |s| s.decrypt_oaep(
            &always,
            &parameters,
            &ciphertext,
            None
        )),
        Err(Error::Runtime(
            pkcs11_runtime::Error::ContextAuthenticationRequired
        ))
    ));
    let label = vec![0; 4097];
    session(&provider, |s| {
        let invalid = RsaOaepParameters {
            label: &label,
            ..parameters
        };
        assert!(s.encrypt_oaep(&public, &invalid, b"input").is_err());
        assert!(
            s.decrypt_oaep(&private, &invalid, &ciphertext, None)
                .is_err()
        );
        s.state()?;
        assert!(
            s.decrypt_oaep(&private, &parameters, &ciphertext, Some(Pin::Value(&pin)))
                .is_err()
        );
        s.state()?;
        // A failed validation must not poison a subsequent operation.
        s.decrypt_oaep(&private, &parameters, &ciphertext, None)?;
        Ok(())
    })
    .unwrap();
    provider.finalize().unwrap();
}
