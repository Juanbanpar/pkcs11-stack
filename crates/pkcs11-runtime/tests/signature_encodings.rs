// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signature encodings and authentication against independent OASIS headers.
#![cfg(unix)]
use pkcs11_runtime::*;
use secrecy::SecretString;
use sha2::{Digest, Sha224};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::{path::PathBuf, process::Command};

struct Fixture(PathBuf);
impl Fixture {
    fn new(source: &str, headers: &str, bits: usize, fault: u8) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "pkcs11-signature-{}-{source}-{bits}-{fault}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let fixture = Self(dir);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let result = Command::new("cc")
            .args([
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fPIC",
                if cfg!(target_os = "macos") {
                    "-dynamiclib"
                } else {
                    "-shared"
                },
            ])
            .arg(format!("-DFAULT={fault}"))
            .arg(format!("-DHASH_BITS={bits}"))
            .arg("-I")
            .arg(root.join("headers").join(headers))
            .arg(root.join(source))
            .arg("-o")
            .arg(fixture.0.join("module.so"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        fixture
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn native_parameters_inputs_permissions_and_context_authentication(
    source: &str,
    headers: &str,
    digest: DigestAlgorithm,
    mgf: DigestAlgorithm,
    hash: &[u8],
) {
    for fault in 0..=6 {
        let fixture = Fixture::new(source, headers, digest.output_len() * 8, fault);
        let module = Module::load(fixture.0.join("module.so")).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let private =
            PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap();
        let public =
            PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap();
        let pin = SecretString::from("1234");
        let mut policy = SigningPolicy::default();
        policy.digests.extend([digest, mgf]);
        let algorithms: &[SignatureAlgorithm] = if fault == 3 {
            &[SignatureAlgorithm::Ecdsa]
        } else {
            &[SignatureAlgorithm::RsaPkcs1, SignatureAlgorithm::RsaPss]
        };
        for &algorithm in algorithms {
            for hashing in [HashingPolicy::TokenOnly, HashingPolicy::SoftwareOnly] {
                policy.hashing = if fault == 5 {
                    HashingPolicy::AllowSoftware
                } else {
                    hashing
                };
                for input in [SignInput::Message(b"abc"), SignInput::Digest(hash)] {
                    let request = SignRequest {
                        algorithm,
                        digest,
                        input,
                        pss: (algorithm == SignatureAlgorithm::RsaPss).then_some(PssParameters {
                            mgf_digest: mgf,
                            salt_len: 20,
                        }),
                    };
                    if fault == 2 || fault == 6 {
                        let result = session.verify(
                            &public,
                            &VerifyRequest {
                                parameters: request,
                                signature: &[0xab; 256],
                            },
                            &policy,
                        );
                        if fault == 6 {
                            assert!(matches!(result, Err(Error::UnsupportedVerification(_))));
                        } else {
                            result.unwrap();
                        }
                        continue;
                    }
                    assert!(
                        session
                            .sign(&private, &request, &SigningPolicy::default(), None)
                            .is_err()
                    );
                    if fault == 4 {
                        assert!(matches!(
                            session.sign(&private, &request, &policy, Some(Pin::Value(&pin))),
                            Err(Error::UnsupportedSigning(_))
                        ));
                        continue;
                    }
                    let missing_pin = session.sign(&private, &request, &policy, None);
                    assert!(
                        matches!(missing_pin, Err(Error::ContextAuthenticationRequired)),
                        "fault={fault}, request={request:?}, error={missing_pin:?}"
                    );
                    let signature =
                        session.sign(&private, &request, &policy, Some(Pin::Value(&pin)));
                    if fault == 1 || fault == 5 {
                        if fault == 1 {
                            assert!(matches!(signature, Err(Error::InvalidSignature)));
                        } else {
                            assert!(matches!(signature, Err(Error::Backend { .. })));
                        }
                        assert!(session.info().is_err());
                        break;
                    }
                    assert_eq!(signature.unwrap().len(), if fault == 3 { 64 } else { 256 });
                    session.info().unwrap();
                }
                if fault == 1 || fault == 5 {
                    break;
                }
            }
            if fault == 1 || fault == 5 {
                break;
            }
        }
        if fault == 0 || fault == 3 {
            let wrong_pin = SecretString::from("wrong");
            let request = SignRequest {
                algorithm: algorithms[0],
                digest,
                input: SignInput::Digest(hash),
                pss: None,
            };
            assert!(matches!(
                session.sign(&private, &request, &policy, Some(Pin::Value(&wrong_pin))),
                Err(Error::Backend { .. })
            ));
            assert!(session.info().is_err());
        }
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}

#[test]
fn sha224_native_encodings() {
    native_parameters_inputs_permissions_and_context_authentication(
        "sha224.c",
        "2.40",
        DigestAlgorithm::Sha224,
        DigestAlgorithm::Sha384,
        &Sha224::digest(b"abc"),
    );
}
#[test]
fn sha3_native_encodings() {
    for (digest, mgf, hash) in [
        (
            DigestAlgorithm::Sha3_224,
            DigestAlgorithm::Sha3_256,
            Sha3_224::digest(b"abc").to_vec(),
        ),
        (
            DigestAlgorithm::Sha3_256,
            DigestAlgorithm::Sha3_384,
            Sha3_256::digest(b"abc").to_vec(),
        ),
        (
            DigestAlgorithm::Sha3_384,
            DigestAlgorithm::Sha3_512,
            Sha3_384::digest(b"abc").to_vec(),
        ),
        (
            DigestAlgorithm::Sha3_512,
            DigestAlgorithm::Sha3_224,
            Sha3_512::digest(b"abc").to_vec(),
        ),
    ] {
        native_parameters_inputs_permissions_and_context_authentication(
            "sha3.c", "3.0", digest, mgf, &hash,
        );
    }
}
