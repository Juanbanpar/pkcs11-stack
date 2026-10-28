// SPDX-License-Identifier: MIT OR Apache-2.0
//! Multipart CLI tags against OpenSSL and existing single-part workflows.
use serde_json::Value;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

#[test]
#[ignore = "requires disposable SoftHSM/Kryoptic runner after runtime MAC fixtures"]
fn multipart_mac_files_stdin_and_native_verification_interoperate() {
    let kdf = std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref() == Ok("1");
    assert!(kdf || std::env::var("PKCS11_TEST_ISOLATED").as_deref() == Ok("1"));
    let module = std::env::var(if kdf {
        "PKCS11_TEST_KDF_MODULE"
    } else {
        "PKCS11_TEST_MODULE"
    })
    .unwrap();
    let token = if kdf { "kdf-test" } else { "client-test" };
    let root = PathBuf::from(
        std::env::var_os(if kdf {
            "PKCS11_TEST_KDF_DIR"
        } else {
            "PKCS11_CLIENT_TEST_DIR"
        })
        .unwrap(),
    )
    .join("cli-mac-multipart");
    std::fs::create_dir(&root).unwrap();
    let pin = root.join("pin");
    std::fs::write(&pin, b"12345678").unwrap();
    let message = root.join("message");
    let tag = root.join("tag");
    let run = |args: &[&str], stdin: Option<&[u8]>| -> Output {
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
    let ok = |out: Output| -> Output {
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };
    let generic = format!("pkcs11:token={token};object=hmac-vector-0-false-32;type=secret-key");
    let caps: Value = serde_json::from_slice(
        &ok(run(
            &[
                "hmac-capabilities",
                "--object",
                &generic,
                "--operation",
                "generate",
            ],
            None,
        ))
        .stdout,
    )
    .unwrap();
    let algorithms = caps["result"]["algorithms"].as_array().unwrap();
    assert!(algorithms.len() >= if kdf { 10 } else { 4 });
    let openssl = std::env::var("PKCS11_TEST_KDF_OPENSSL").unwrap_or_else(|_| "openssl".into());
    let mut profiles = Vec::new();
    for (index, (algorithm, full)) in [
        ("hmac-sha256", 32),
        ("hmac-sha384", 48),
        ("hmac-sha512", 64),
        ("hmac-sha224", 28),
        ("hmac-sha512-224", 28),
        ("hmac-sha512-256", 32),
        ("hmac-sha3-224", 28),
        ("hmac-sha3-256", 32),
        ("hmac-sha3-384", 48),
        ("hmac-sha3-512", 64),
    ]
    .into_iter()
    .enumerate()
    {
        if !algorithms.iter().any(|a| a == algorithm) {
            continue;
        }
        let uri =
            format!("pkcs11:token={token};object=hmac-vector-{index}-false-{full};type=secret-key");
        profiles.push((Some(algorithm), uri, full, "0b".repeat(full)));
    }
    for bits in [128, 192, 256] {
        profiles.push((
            None,
            format!("pkcs11:token={token};object=cmac-vector-{bits};type=secret-key"),
            16,
            "42".repeat(bits / 8),
        ));
    }
    for (algorithm, uri, full, key) in profiles {
        let generate = if algorithm.is_some() {
            "mac-hmac"
        } else {
            "mac-aes-cmac"
        };
        let verify = if algorithm.is_some() {
            "verify-hmac"
        } else {
            "verify-aes-cmac"
        };
        for length in [0, 1, 1_000_003] {
            let bytes = vec![0xA5; length];
            std::fs::write(&message, &bytes).unwrap();
            let mut command = Command::new(&openssl);
            if let Some(algorithm) = algorithm {
                command.args([
                    "dgst",
                    &format!("-{}", algorithm.strip_prefix("hmac-").unwrap()),
                    "-mac",
                    "HMAC",
                    "-macopt",
                    &format!("hexkey:{key}"),
                    "-binary",
                    message.to_str().unwrap(),
                ]);
            } else {
                command.args([
                    "mac",
                    "-macopt",
                    &format!("cipher:AES-{}-CBC", key.len() * 4),
                    "-macopt",
                    &format!("hexkey:{key}"),
                    "-in",
                    message.to_str().unwrap(),
                    "-binary",
                    "CMAC",
                ]);
            }
            let expected = ok(command.output().unwrap()).stdout;
            assert_eq!(expected.len(), full);
            let mut base = vec!["--object", &uri];
            if let Some(algorithm) = algorithm {
                base.extend(["--algorithm", algorithm]);
            }
            for tag_length in [None, Some(full / 2), Some(full)]
                .into_iter()
                .filter(|n| n.is_none() || kdf)
            {
                let tag_length_string = tag_length.unwrap_or(full).to_string();
                let mut profile = base.clone();
                if tag_length.is_some() {
                    profile.extend(["--tag-length", &tag_length_string]);
                }
                let mut args = vec![generate];
                args.extend(&profile);
                args.extend([
                    "--input",
                    message.to_str().unwrap(),
                    "--output",
                    "-",
                    "--multipart",
                ]);
                let out = ok(run(&args, None));
                assert_eq!(out.stdout, expected[..tag_length.unwrap_or(full)]);
                std::fs::write(&tag, &out.stdout).unwrap();
                let mut verification = vec![verify];
                verification.extend(&profile);
                verification.extend([
                    "--input",
                    message.to_str().unwrap(),
                    "--tag-file",
                    tag.to_str().unwrap(),
                ]);
                ok(run(&verification, None));
                verification.push("--multipart");
                ok(run(&verification, None));
                let mut wrong = out.stdout;
                wrong[0] ^= 1;
                std::fs::write(&tag, wrong).unwrap();
                let out = run(&verification, None);
                assert_eq!(out.status.code(), Some(4));
                assert!(out.stdout.is_empty());
                // The same original bytes and profile also work over stdin.
                if length == 1_000_003 && tag_length.is_none() {
                    let position = args.iter().position(|arg| *arg == "--input").unwrap() + 1;
                    args[position] = "-";
                    assert_eq!(ok(run(&args, Some(&bytes))).stdout, expected);
                    std::fs::write(&tag, &expected).unwrap();
                    let position = verification
                        .iter()
                        .position(|arg| *arg == "--input")
                        .unwrap()
                        + 1;
                    verification[position] = "-";
                    ok(run(&verification, Some(&bytes)));
                }
            }
        }
    }
}
