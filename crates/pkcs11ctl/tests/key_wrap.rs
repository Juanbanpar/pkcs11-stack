// SPDX-License-Identifier: MIT OR Apache-2.0
//! Actual CLI key-wrap workflows on the disposable provider stores.
use serde_json::Value;
use std::{
    path::PathBuf,
    process::{Command, Output},
};

#[test]
#[ignore = "requires a disposable SoftHSM or Kryoptic runner"]
fn key_wrap_commands_interoperate_and_preserve_output_policy() {
    let kryoptic = std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref() == Ok("1");
    if !kryoptic {
        assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    }
    let module = std::env::var(if kryoptic {
        "PKCS11_TEST_KDF_MODULE"
    } else {
        "PKCS11_TEST_MODULE"
    })
    .unwrap();
    let root = PathBuf::from(
        std::env::var_os(if kryoptic {
            "PKCS11_TEST_KDF_DIR"
        } else {
            "PKCS11_CLIENT_TEST_DIR"
        })
        .unwrap(),
    );
    let pin = root.join("cli-key-wrap.pin");
    std::fs::write(&pin, b"12345678\n").unwrap();
    let pin = pin.to_str().unwrap();
    let wrapping = if kryoptic {
        "pkcs11:token=kdf-test;id=%F4%A0%00;type=secret-key"
    } else {
        "pkcs11:token=client-test;id=%40;type=secret-key"
    };
    let target = if kryoptic {
        "pkcs11:token=kdf-test;id=%F4%A1%00;type=secret-key"
    } else {
        "pkcs11:token=client-test;id=%41;type=secret-key"
    };
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args(["--module", &module, "--format", "json"])
            .args(args)
            .output()
            .unwrap()
    };
    let ok = |output: Output| {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    let output = ok(run(&[
        "key-wrap-capabilities",
        "--object",
        wrapping,
        "--operation",
        "wrap",
        "--pin-file",
        pin,
    ]));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    let algorithms = result["result"]["algorithms"].as_array().unwrap();
    assert!(algorithms.contains(&Value::from("kw")));
    if kryoptic {
        assert!(algorithms.contains(&Value::from("kwp")));
    }
    let plaintext = if kryoptic {
        (0..16).collect::<Vec<u8>>()
    } else {
        vec![
            0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF,
        ]
    };
    let input = root.join("cli-key-wrap-public-vector");
    std::fs::write(&input, &plaintext).unwrap();
    let key: String = (0..if kryoptic { 16 } else { 32 })
        .map(|b| format!("{b:02x}"))
        .collect();
    for algorithm in algorithms {
        let algorithm = algorithm.as_str().unwrap();
        let blob = root.join(format!("cli-key-wrap-{algorithm}"));
        let expected = root.join(format!("cli-key-wrap-{algorithm}-expected"));
        let cipher = format!(
            "-id-aes{}-wrap{}",
            if kryoptic { 128 } else { 256 },
            if algorithm == "kwp" { "-pad" } else { "" }
        );
        let output = Command::new("openssl")
            .args([
                "enc",
                &cipher,
                "-K",
                &key,
                "-iv",
                if algorithm == "kwp" {
                    "A65959A6"
                } else {
                    "A6A6A6A6A6A6A6A6"
                },
                "-in",
            ])
            .arg(&input)
            .arg("-out")
            .arg(&expected)
            .output()
            .unwrap();
        assert!(output.status.success());
        let args = [
            "wrap-aes-key",
            "--object",
            wrapping,
            "--target",
            target,
            "--algorithm",
            algorithm,
            "--output",
            blob.to_str().unwrap(),
            "--pin-file",
            pin,
        ];
        assert!(ok(run(&args)).stdout.is_empty());
        assert_eq!(
            std::fs::read(&blob).unwrap(),
            std::fs::read(expected).unwrap()
        );
        assert_eq!(run(&args).status.code(), Some(6));
        let id = if algorithm == "kw" {
            "F4B000"
        } else {
            "F4B001"
        };
        let args = [
            "unwrap-aes-key",
            "--object",
            wrapping,
            "--algorithm",
            algorithm,
            "--input",
            blob.to_str().unwrap(),
            "--id",
            id,
            "--label",
            "CLI unwrapped AES",
            "--confirm",
            "--pin-file",
            pin,
        ];
        ok(run(&args));
        assert_eq!(run(&args).status.code(), Some(2));
        let unwrapped = format!(
            "pkcs11:token={};id=%F4%B0%{};type=secret-key",
            if kryoptic { "kdf-test" } else { "client-test" },
            if algorithm == "kw" { "00" } else { "01" }
        );
        let attrs = ok(run(&[
            "inspect",
            "--object",
            &unwrapped,
            "--attributes",
            "sensitive,extractable,encrypt,decrypt,wrap,unwrap,derive,sign,verify",
            "--pin-file",
            pin,
        ]));
        let attrs: Value = serde_json::from_slice(&attrs.stdout).unwrap();
        for (name, value) in [
            ("sensitive", true),
            ("extractable", false),
            ("encrypt", true),
            ("decrypt", true),
            ("wrap", false),
            ("unwrap", false),
            ("derive", false),
            ("sign", false),
            ("verify", false),
        ] {
            assert_eq!(attrs["result"][name]["value"], value);
        }
        let rejected = root.join(format!("cli-key-wrap-{algorithm}-forbidden"));
        assert_eq!(
            run(&[
                "wrap-aes-key",
                "--object",
                wrapping,
                "--target",
                &unwrapped,
                "--algorithm",
                algorithm,
                "--output",
                rejected.to_str().unwrap(),
                "--pin-file",
                pin
            ])
            .status
            .code(),
            Some(4)
        );
        assert!(!rejected.exists());
        let mut invalid = std::fs::read(&blob).unwrap();
        invalid[0] ^= 1;
        std::fs::write(&blob, invalid).unwrap();
        let output = run(&[
            "unwrap-aes-key",
            "--object",
            wrapping,
            "--algorithm",
            algorithm,
            "--input",
            blob.to_str().unwrap(),
            "--id",
            "F4B002",
            "--label",
            "Invalid CLI unwrap",
            "--confirm",
            "--pin-file",
            pin,
        ]);
        assert_eq!(output.status.code(), Some(5));
    }
}
