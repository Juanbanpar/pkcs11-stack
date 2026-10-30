// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI input modes agree with the independently verified client signatures.
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
fn ok(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh after the HashML-DSA client test"]
fn hash_ml_dsa_cli_modes_context_authentication_stdin_and_independent_signatures() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let pin = root.join("hash-cli.pin");
    std::fs::write(&pin, b"12345678").unwrap();
    let context = root.join("hash-cli.context");
    std::fs::write(&context, b"context").unwrap();
    let input = root.join("hash-cli.input");
    std::fs::write(&input, b"abc").unwrap();
    let digest = root.join("hash-cli.digest");
    let hash = Command::new(std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap())
        .args([
            "dgst",
            "-sha512",
            "-binary",
            "-out",
            digest.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    ok(&hash);
    let run = |args: &[&str], stdin: Option<&[u8]>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command
            .arg("--module")
            .arg(&module)
            .args(["--format", "json"])
            .args(args)
            .arg("--pin-file")
            .arg(&pin)
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
    for (index, parameter) in ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]
        .into_iter()
        .enumerate()
    {
        let private = format!("pkcs11:token=kdf-test;id=%E1%{index:02X};type=private");
        let public = private.replace("private", "public");
        let expected = std::fs::read(root.join(format!("hash-mldsa-{index}.sig"))).unwrap();
        let signature = root.join(format!("hash-cli-{index}.sig"));
        for mode in ["message", "digest"] {
            let caps = run(
                &[
                    "hash-ml-dsa-capabilities",
                    "--object",
                    &private,
                    "--input-kind",
                    mode,
                ],
                None,
            );
            ok(&caps);
            let value: serde_json::Value = serde_json::from_slice(&caps.stdout).unwrap();
            assert_eq!(value["result"]["can_sign"], true);
            let bytes = if mode == "message" {
                b"abc".to_vec()
            } else {
                std::fs::read(&digest).unwrap()
            };
            let mut args = vec![
                "sign-hash-ml-dsa",
                "--object",
                &private,
                "--parameter-set",
                parameter,
                "--input-kind",
                mode,
                "--context-file",
                context.to_str().unwrap(),
                "--input",
                "-",
                "--hedging",
                "deterministic",
                "--output",
                "-",
            ];
            if index == 1 {
                args.extend(["--context-pin-file", pin.to_str().unwrap()]);
            }
            let signed = run(&args, Some(&bytes));
            ok(&signed);
            assert_eq!(signed.stdout, expected);
            std::fs::write(&signature, &signed.stdout).unwrap();
            let verified = run(
                &[
                    "verify-hash-ml-dsa",
                    "--object",
                    &public,
                    "--parameter-set",
                    parameter,
                    "--input-kind",
                    mode,
                    "--context-file",
                    context.to_str().unwrap(),
                    "--input",
                    "-",
                    "--signature",
                    signature.to_str().unwrap(),
                ],
                Some(&bytes),
            );
            ok(&verified);
            let value: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
            assert_eq!(value["result"]["verified"], true);
            let changed = if mode == "message" {
                b"abd".to_vec()
            } else {
                vec![0; 64]
            };
            let failed = run(
                &[
                    "verify-hash-ml-dsa",
                    "--object",
                    &public,
                    "--parameter-set",
                    parameter,
                    "--input-kind",
                    mode,
                    "--context-file",
                    context.to_str().unwrap(),
                    "--input",
                    "-",
                    "--signature",
                    signature.to_str().unwrap(),
                ],
                Some(&changed),
            );
            assert!(!failed.status.success());
            assert!(failed.stdout.is_empty());
        }

        for domain in [vec![], b"context".to_vec(), vec![0xA5; 255]] {
            std::fs::write(&context, &domain).unwrap();
            for length in [0, 3, 1_000_003] {
                let bytes = if length == 3 {
                    b"abc".to_vec()
                } else {
                    (0..length).map(|i| (i % 251) as u8).collect()
                };
                std::fs::write(&input, &bytes).unwrap();
                let expected = std::fs::read(
                    root.join(format!("hash-stream-{index}-{}-{length}.sig", domain.len())),
                )
                .unwrap();
                for file_input in [false, true] {
                    let mut args = vec![
                        "sign-hash-ml-dsa",
                        "--object",
                        &private,
                        "--parameter-set",
                        parameter,
                        "--multipart",
                        "--context-file",
                        context.to_str().unwrap(),
                        "--input",
                        if file_input {
                            input.to_str().unwrap()
                        } else {
                            "-"
                        },
                        "--hedging",
                        "deterministic",
                        "--output",
                        "-",
                    ];
                    if index == 1 {
                        args.extend(["--context-pin-file", pin.to_str().unwrap()]);
                    }
                    let signed = run(&args, (!file_input).then_some(bytes.as_slice()));
                    ok(&signed);
                    assert_eq!(signed.stdout, expected);
                    std::fs::write(&signature, &signed.stdout).unwrap();
                    let verified = run(
                        &[
                            "verify-hash-ml-dsa",
                            "--object",
                            &public,
                            "--parameter-set",
                            parameter,
                            "--multipart",
                            "--context-file",
                            context.to_str().unwrap(),
                            "--input",
                            if file_input {
                                input.to_str().unwrap()
                            } else {
                                "-"
                            },
                            "--signature",
                            signature.to_str().unwrap(),
                        ],
                        (!file_input).then_some(bytes.as_slice()),
                    );
                    ok(&verified);
                }
            }
        }
        std::fs::write(&context, b"context").unwrap();
    }
}
