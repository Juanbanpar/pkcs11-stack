// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real-provider streaming signatures, binding, native and certificate verification.
use der::{Encode, Sequence, asn1::UintRef};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
#[derive(Sequence)]
struct EcdsaSignature<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}
fn ok(output: Output) -> Output {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
#[test]
#[ignore = "requires disposable SoftHSM runner and client certificate fixtures"]
fn multipart_signing_binding_and_verification_interoperate() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let module = std::env::var("PKCS11_TEST_MODULE").unwrap();
    let fixtures = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let root = fixtures.join("cli-signature-multipart");
    std::fs::create_dir(&root).unwrap();
    let pin = root.join("pin");
    std::fs::write(&pin, b"12345678").unwrap();
    let message = root.join("message");
    let signature = root.join("signature");
    let run = |args: &[&str], stdin: Option<&[u8]>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command
            .args(["--module", &module, "--format", "json"])
            .args(args)
            .args(["--pin-file", pin.to_str().unwrap()]);
        command
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        if let Some(bytes) = stdin {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        }
        child.wait_with_output().unwrap()
    };
    let required_ec = std::env::var("PKCS11_TEST_REQUIRE_EC_MULTIPART").as_deref() == Ok("1");
    let required_sha3 = std::env::var("PKCS11_TEST_REQUIRE_SHA3_SIGNATURES").as_deref() == Ok("1");
    for (label, id, algorithm) in [
        ("wrong", "05", "rsa-pkcs1"),
        ("wrong", "05", "rsa-pss"),
        ("p256", "02", "ecdsa"),
        ("p384", "03", "ecdsa"),
        ("p521", "04", "ecdsa"),
    ] {
        let key = format!("pkcs11:token=client-test;object={label};type=private");
        let public = format!("pkcs11:token=client-test;object={label};type=public");
        let certificate = format!("pkcs11:token=client-test;object={label};type=cert");
        for digest in [
            "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512",
        ]
        .into_iter()
        .filter(|d| !d.starts_with("sha3-") || required_sha3)
        {
            for hashing in ["token", "allow-software", "software"] {
                for length in if digest == "sha256" {
                    vec![0, 1, 1_000_003]
                } else {
                    vec![19]
                } {
                    let bytes = vec![0xA5; length];
                    std::fs::write(&message, &bytes).unwrap();
                    let salt = if digest == "sha224" || digest == "sha3-224" {
                        "28"
                    } else {
                        "32"
                    };
                    let mut parameters = vec!["--algorithm", algorithm, "--digest", digest];
                    if algorithm == "rsa-pss" {
                        parameters.extend(["--mgf-digest", digest, "--salt-length", salt]);
                    }
                    let mut args = vec![
                        "sign",
                        "--key",
                        &key,
                        "--certificate",
                        &certificate,
                        "--hashing",
                        hashing,
                        "--input",
                        message.to_str().unwrap(),
                        "--output",
                        "-",
                        "--multipart",
                    ];
                    args.extend(&parameters);
                    let result = run(&args, None);
                    if algorithm == "ecdsa" && hashing != "software" && !required_ec {
                        assert_eq!(
                            result.status.code(),
                            Some(5),
                            "{}",
                            String::from_utf8_lossy(&result.stderr)
                        );
                        assert!(result.stdout.is_empty());
                        continue;
                    }
                    let signed = ok(result).stdout;
                    std::fs::write(&signature, &signed).unwrap();
                    let mut verify = vec![
                        "verify-token",
                        "--key",
                        &public,
                        "--hashing",
                        hashing,
                        "--input",
                        message.to_str().unwrap(),
                        "--signature",
                        signature.to_str().unwrap(),
                        "--multipart",
                    ];
                    verify.extend(&parameters);
                    ok(run(&verify, None));
                    // Existing single-part native verification accepts streamed signatures.
                    verify.retain(|arg| *arg != "--multipart");
                    ok(run(&verify, None));
                    let mut certificate_verify = vec![
                        "verify",
                        "--certificate",
                        &certificate,
                        "--input",
                        message.to_str().unwrap(),
                        "--signature",
                        signature.to_str().unwrap(),
                        "--multipart",
                    ];
                    certificate_verify.extend(&parameters);
                    ok(run(&certificate_verify, None));
                    let external = root.join("external.sig");
                    let encoded = if algorithm == "ecdsa" {
                        let width = signed.len() / 2;
                        EcdsaSignature {
                            r: UintRef::new(&signed[..width]).unwrap(),
                            s: UintRef::new(&signed[width..]).unwrap(),
                        }
                        .to_der()
                        .unwrap()
                    } else {
                        signed.clone()
                    };
                    std::fs::write(&external, encoded).unwrap();
                    let public_pem = fixtures.join(format!("{id}-public.pem"));
                    let mut command = Command::new("openssl");
                    command.args([
                        "dgst",
                        &format!("-{digest}"),
                        "-verify",
                        public_pem.to_str().unwrap(),
                        "-signature",
                        external.to_str().unwrap(),
                    ]);
                    if algorithm == "rsa-pss" {
                        command.args([
                            "-sigopt",
                            "rsa_padding_mode:pss",
                            "-sigopt",
                            &format!("rsa_pss_saltlen:{salt}"),
                        ]);
                    }
                    command.arg(&message);
                    ok(command.output().unwrap());
                    let mut wrong = signed;
                    wrong[0] ^= 1;
                    std::fs::write(&signature, wrong).unwrap();
                    verify.push("--multipart");
                    let result = run(&verify, None);
                    assert_eq!(result.status.code(), Some(4));
                    assert!(result.stdout.is_empty());
                    if length == 1_000_003 && hashing == "software" {
                        let position = args.iter().position(|arg| *arg == "--input").unwrap() + 1;
                        args[position] = "-";
                        let signed = ok(run(&args, Some(&bytes))).stdout;
                        std::fs::write(&signature, signed).unwrap();
                        let position = verify.iter().position(|arg| *arg == "--input").unwrap() + 1;
                        verify[position] = "-";
                        ok(run(&verify, Some(&bytes)));
                    }
                }
            }
        }
    }
    // A pipe can be signed exactly once and checked against the bound certificate.
    let bytes = vec![0x42; 64 * 1024 * 1024];
    let args = [
        "sign",
        "--key",
        "pkcs11:token=client-test;object=always;type=private",
        "--certificate",
        "pkcs11:token=client-test;object=always;type=cert",
        "--algorithm",
        "rsa-pkcs1",
        "--digest",
        "sha256",
        "--hashing",
        "token",
        "--input",
        "-",
        "--output",
        "-",
        "--context-pin-file",
        pin.to_str().unwrap(),
        "--multipart",
    ];
    let signed = ok(run(&args, Some(&bytes))).stdout;
    let certificate =
        pkcs11_client::Certificate::from_der(std::fs::read(fixtures.join("06-cert.der")).unwrap())
            .unwrap();
    certificate
        .verify_reader(
            pkcs11_client::SignatureParameters {
                algorithm: pkcs11_client::SignatureAlgorithm::RsaPkcs1,
                digest: pkcs11_client::DigestAlgorithm::Sha256,
                pss: None,
            },
            &mut &bytes[..],
            &signed,
        )
        .unwrap();
}
