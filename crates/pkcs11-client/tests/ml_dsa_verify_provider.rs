// SPDX-License-Identifier: MIT OR Apache-2.0
//! Required signature-first readers, independent verification and provider cleanup.
use pkcs11_client::*;
use secrecy::SecretString;
use std::{
    io::{self, Read},
    path::PathBuf,
    process::Command,
};
struct Chunks<'a> {
    bytes: io::Cursor<&'a [u8]>,
    maximum: usize,
    interrupted: bool,
}
impl Read for Chunks<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.maximum = self.maximum.max(out.len());
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let length = out.len().min(3071);
        self.bytes.read(&mut out[..length])
    }
}
fn openssl(args: &[&str]) {
    let result = Command::new(std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap())
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "OpenSSL verification failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}
#[test]
#[ignore = "requires the disposable Kryoptic runner with ML-DSA enabled"]
fn signature_first_readers_contexts_independent_verification_and_failures() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=kdf-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let mut session = provider
        .management(
            &token,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    let data: Vec<u8> = (0..1_000_003).map(|i| (i % 251) as u8).collect();
    let sets = [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ];
    for (index, parameter_set) in sets.into_iter().enumerate() {
        session
            .generate_ml_dsa_key_pair(
                parameter_set,
                &[0xD7, index as u8],
                b"signature-first-client",
                index == 1,
            )
            .unwrap();
        let private = PrivateKeyRef::new(
            format!("pkcs11:token=kdf-test;id=%D7%{index:02X};type=private")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let public = PublicKeyRef::new(
            format!("pkcs11:token=kdf-test;id=%D7%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let context_pin = || (index == 1).then_some(Pin::Value(&pin));
        let caps = session.ml_dsa_verification_capabilities(&public).unwrap();
        assert!(caps.can_verify && caps.can_stream);
        let spki = session.export_ml_dsa_public_key(&public).unwrap();
        let verifier = MlDsaVerifyingKey::from_spki_der(&spki).unwrap();
        for context in [&[][..], &[0xA5; 255], b"client-context"] {
            for message in [&[][..], &data[..]] {
                let parameters = MlDsaParameters {
                    parameter_set,
                    context,
                    hedging: MlDsaHedging::Deterministic,
                };
                let request = parameters.request(message);
                let signature = session
                    .sign_ml_dsa(
                        &private,
                        &request,
                        &MlDsaSigningPolicy::default(),
                        context_pin(),
                    )
                    .unwrap();
                verifier.verify_signature(&request, &signature).unwrap();
                // Hedging does not affect verification, even when it differs from signing.
                let parameters = MlDsaParameters {
                    hedging: MlDsaHedging::Required,
                    ..parameters
                };
                session
                    .verify_ml_dsa_signature_first(
                        &public,
                        &parameters.request(message),
                        &signature,
                    )
                    .unwrap();
                let mut reader = Chunks {
                    bytes: io::Cursor::new(message),
                    maximum: 0,
                    interrupted: false,
                };
                session
                    .verify_ml_dsa_reader(&public, parameters, &signature, &mut reader)
                    .unwrap();
                assert_eq!(reader.maximum, 65536);
                assert_eq!(reader.bytes.position(), message.len() as u64);
                let mut altered = signature.clone();
                altered[0] ^= 1;
                let error = session
                    .verify_ml_dsa_reader(
                        &public,
                        parameters,
                        &altered,
                        &mut io::Cursor::new(message),
                    )
                    .unwrap_err();
                assert!(matches!(error, Error::SignatureMismatch));
                assert_eq!(error.kind(), ErrorKind::Client);
                session.state().unwrap();
                let error = session
                    .verify_ml_dsa_reader(
                        &public,
                        parameters,
                        &signature,
                        &mut io::Cursor::new(b"changed"),
                    )
                    .unwrap_err();
                assert!(matches!(error, Error::SignatureMismatch));
                session.state().unwrap();
                let error = session
                    .verify_ml_dsa_reader(
                        &public,
                        MlDsaParameters {
                            context: b"wrong-context",
                            ..parameters
                        },
                        &signature,
                        &mut io::Cursor::new(message),
                    )
                    .unwrap_err();
                assert!(matches!(error, Error::SignatureMismatch));
                session.state().unwrap();
                // pkeyutl rejects zero-byte oneshot input; RustCrypto covers empty messages.
                if context == b"client-context" && !message.is_empty() {
                    let public_path = root.join(format!("signature-first-{index}.der"));
                    let input_path = root.join(format!("signature-first-{index}.message"));
                    let sig_path = root.join(format!("signature-first-{index}.sig"));
                    std::fs::write(&public_path, &spki).unwrap();
                    std::fs::write(&input_path, message).unwrap();
                    std::fs::write(&sig_path, &signature).unwrap();
                    openssl(&[
                        "pkeyutl",
                        "-verify",
                        "-pubin",
                        "-inkey",
                        public_path.to_str().unwrap(),
                        "-keyform",
                        "DER",
                        "-in",
                        input_path.to_str().unwrap(),
                        "-sigfile",
                        sig_path.to_str().unwrap(),
                        "-pkeyopt",
                        "context-string:client-context",
                    ]);
                }
            }
        }
    }
    struct Failed;
    impl Read for Failed {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("reader error canary"))
        }
    }
    let public = PublicKeyRef::new(
        "pkcs11:token=kdf-test;id=%D7%00;type=public"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let error = session
        .verify_ml_dsa_reader(
            &public,
            MlDsaParameters {
                parameter_set: sets[0],
                context: &[],
                hedging: MlDsaHedging::Preferred,
            },
            &vec![0; sets[0].signature_length()],
            &mut Failed,
        )
        .unwrap_err();
    assert!(matches!(error, Error::SignatureInput));
    assert_eq!(error.kind(), ErrorKind::Input);
    assert!(!format!("{error:?} {error}").contains("canary"));
    assert!(session.state().is_err());
    session.close().unwrap();
    provider.finalize().unwrap();
}
