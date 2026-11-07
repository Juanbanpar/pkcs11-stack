// SPDX-License-Identifier: MIT OR Apache-2.0
//! CCM bounds, native faults and output withheld through checked cleanup.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod fixture;
use std::{
    path::Path,
    process::{Command, Output},
};
fn run(module: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .arg("--module")
        .arg(module)
        .args(["--format", "json"])
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn chacha_native_failures_and_cleanup_never_release_output() {
    for decrypt in [false, true] {
        for fault in [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 25,
            26, 27, 28,
        ] {
            let fixture =
                fixture::MetadataModule::with_case("chacha20_poly1305.c", 3000 + fault, "3.2");
            let root = fixture.path().parent().unwrap();
            let input = root.join("input");
            let output = root.join("out");
            let ciphertext = b"abc"
                .iter()
                .map(|b| b ^ 0x80)
                .chain([0xef; 16])
                .collect::<Vec<_>>();
            std::fs::write(
                &input,
                if decrypt {
                    ciphertext.as_slice()
                } else {
                    b"abc"
                },
            )
            .unwrap();
            let mut args = vec![
                if decrypt {
                    "decrypt-chacha20-poly1305"
                } else {
                    "encrypt-chacha20-poly1305"
                },
                "--object",
                "pkcs11:token=cmac;id=%01;type=secret-key",
                "--nonce",
                "a5a5a5a5a5a5a5a5a5a5a5a5",
                "--input",
                input.to_str().unwrap(),
                "--output",
                output.to_str().unwrap(),
            ];
            let fails = matches!(fault,5..=8|12|16..=22|25..=28)
                || if decrypt {
                    matches!(fault, 2 | 4 | 13 | 14)
                } else {
                    matches!(fault, 1 | 3 | 10 | 11)
                };
            let result = run(fixture.path(), &args);
            assert_eq!(
                result.status.success(),
                !fails,
                "{fault}/{decrypt}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            if fails {
                assert!(!output.exists());
                assert!(result.stdout.is_empty());
                args[8] = "-";
                let result = run(fixture.path(), &args);
                assert!(!result.status.success());
                assert!(result.stdout.is_empty());
                args[8] = output.to_str().unwrap();
            } else {
                assert_eq!(
                    std::fs::read(&output).unwrap(),
                    if decrypt { b"abc".to_vec() } else { ciphertext }
                );
            }
            std::fs::write(&output, b"preserve").unwrap();
            assert!(!run(fixture.path(), &args).status.success());
            assert_eq!(std::fs::read(&output).unwrap(), b"preserve");
        }
    }
}
#[test]
fn chacha_invalid_inputs_fail_before_loading_the_provider() {
    let fixture = fixture::MetadataModule::with_case("chacha20_poly1305.c", 3000, "3.2");
    let root = fixture.path().parent().unwrap();
    let input = root.join("input");
    let output = root.join("out");
    let aad = root.join("aad");
    std::fs::write(&input, [0; 15]).unwrap();
    std::fs::write(&aad, vec![0; 1024 * 1024 + 1]).unwrap();
    let module = Path::new("/missing-ccm-provider.so");
    let base = vec![
        "encrypt-chacha20-poly1305",
        "--object",
        "pkcs11:token=cmac;id=%01;type=secret-key",
        "--nonce",
        "a5a5a5a5a5a5a5a5a5a5a5a5",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ];
    let mut cases = vec![];
    let mut args = base.clone();
    args[4] = "00";
    cases.push(args);
    let mut args = base.clone();
    args[2] = "pkcs11:token=cmac;id=%01;type=private";
    cases.push(args);
    let mut args = base.clone();
    args[0] = "decrypt-chacha20-poly1305";
    cases.push(args);
    for extra in [
        vec!["--multipart"],
        vec!["--message-api"],
        vec!["--aad-file", "-"],
        vec!["--role", "so"],
        vec!["--aad-file", aad.to_str().unwrap()],
    ] {
        let mut args = base.clone();
        args.extend(extra);
        cases.push(args);
    }
    for args in cases {
        let out = run(module, &args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty());
        assert!(!output.exists());
    }
    std::fs::OpenOptions::new()
        .write(true)
        .open(&input)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    assert_eq!(run(module, &base).status.code(), Some(2));
    assert!(!output.exists());
}

#[test]
fn protected_generation_and_cleanup_output_contracts() {
    for fault in [0, 27, 28, 30, 31, 32, 33, 34, 35, 36] {
        let fixture =
            fixture::MetadataModule::with_case("chacha20_poly1305.c", 3100 + fault, "3.2");
        let args = [
            "generate",
            "--token",
            "pkcs11:token=cmac",
            "--kind",
            "chacha20-poly1305",
            "--id",
            "6672657368",
            "--label",
            "fresh",
            "--confirm",
        ];
        let result = run(fixture.path(), &args);
        assert_eq!(
            result.status.success(),
            fault == 0,
            "{fault}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        if fault == 0 {
            let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(value["result"]["extractable"], false);
            assert_eq!(value["result"]["key"]["bits"], 256);
        } else {
            assert!(result.stdout.is_empty());
        }
    }
    let base = vec![
        "generate",
        "--token",
        "pkcs11:token=cmac",
        "--kind",
        "chacha20-poly1305",
        "--id",
        "6672657368",
        "--label",
        "fresh",
        "--confirm",
    ];
    for extra in [
        vec!["--bits", "256"],
        vec!["--purpose", "encryption"],
        vec!["--always-authenticate"],
        vec!["--general-tag"],
        vec!["--role", "so"],
    ] {
        let mut args = base.clone();
        args.extend(extra);
        let result = run(Path::new("/missing-provider.so"), &args);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
    }
    for (index, replacement) in [(6, ""), (8, "")] {
        let mut args = base.clone();
        args[index] = replacement;
        let result = run(Path::new("/missing-provider.so"), &args);
        assert_eq!(result.status.code(), Some(2));
    }
}
