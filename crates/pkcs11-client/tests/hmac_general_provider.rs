// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native general HMAC client profiles and reusable verification mismatches.
use pkcs11_client::{
    Authentication, Error, HmacAlgorithm, MacOperation, Pin, Provider, SessionMode,
};
use secrecy::SecretString;

#[test]
#[ignore = "requires the disposable Kryoptic runner after runtime HMAC fixtures"]
fn general_hmac_client_native_tags_and_reusable_mismatches() {
    use pkcs11_client::{HmacTagProfile, object_reference};
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=kdf-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let mut session = provider
        .management(
            &token,
            SessionMode::ReadOnly,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    for (index, algorithm) in HmacAlgorithm::ALL.into_iter().enumerate() {
        let key = object_reference(
            format!(
                "pkcs11:token=kdf-test;object=hmac-vector-{index}-false-{};type=secret-key",
                algorithm.tag_length()
            )
            .parse()
            .unwrap(),
        )
        .unwrap();
        let options = session.hmac_options(&key, MacOperation::Generate).unwrap();
        for profile in HmacTagProfile::choices(algorithm).into_iter().skip(1) {
            assert!(options.supports(algorithm, profile));
            let tag = session
                .mac_hmac_with_profile(&key, algorithm, b"client general", profile)
                .unwrap();
            assert_eq!(tag.len(), profile.tag_length(algorithm));
            assert_eq!(
                session
                    .hmac_reader(&key, algorithm, profile, &mut &b"client general"[..])
                    .unwrap(),
                tag
            );
            session
                .verify_hmac_reader(&key, algorithm, profile, &mut &b"client general"[..], &tag)
                .unwrap();
            assert!(matches!(
                session.verify_hmac_reader(&key, algorithm, profile, &mut &b"changed"[..], &tag),
                Err(Error::MacMismatch)
            ));
            session.state().unwrap();
            session
                .verify_hmac_with_profile(&key, algorithm, b"client general", &tag, profile)
                .unwrap();
            assert!(matches!(
                session.verify_hmac_with_profile(&key, algorithm, b"changed", &tag, profile),
                Err(Error::MacMismatch)
            ));
            session.state().unwrap();
        }
        if index == 0 {
            use std::{
                io::{Read, copy},
                process::{Command, Stdio},
            };
            let length = 17 * 1024 * 1024 + 3;
            let mut child = Command::new(std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap())
                .args([
                    "dgst",
                    "-sha256",
                    "-mac",
                    "HMAC",
                    "-macopt",
                    &format!("hexkey:{}", "0b".repeat(32)),
                    "-binary",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            copy(
                &mut std::io::repeat(0xA5).take(length),
                &mut child.stdin.take().unwrap(),
            )
            .unwrap();
            let expected = child.wait_with_output().unwrap();
            assert!(expected.status.success());
            for profile in [
                HmacTagProfile::Full,
                HmacTagProfile::General { tag_length: 16 },
            ] {
                let tag = session
                    .hmac_reader(
                        &key,
                        algorithm,
                        profile,
                        &mut std::io::repeat(0xA5).take(length),
                    )
                    .unwrap();
                assert_eq!(tag, expected.stdout[..profile.tag_length(algorithm)]);
                session
                    .verify_hmac_reader(
                        &key,
                        algorithm,
                        profile,
                        &mut std::io::repeat(0xA5).take(length),
                        &tag,
                    )
                    .unwrap();
                session.state().unwrap();
            }
        }
    }
    session.close().unwrap();
    provider.finalize().unwrap();
}
