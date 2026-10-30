// SPDX-License-Identifier: MIT OR Apache-2.0
//! Exact curveName parameters, context authentication and checked CLI output.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use std::{
    io::Write,
    process::{Command, Stdio},
};
#[test]
fn named_cli_context_login_native_failures_and_cleanup_withhold_signatures() {
    for (index, scheme, length) in [
        (0, "ed25519", 64),
        (1, "ed25519ctx", 64),
        (2, "ed25519ph", 64),
        (3, "ed448", 114),
        (4, "ed448ph", 114),
    ] {
        for fault in [
            0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25,
        ] {
            let fixture = MetadataModule::from_source("eddsa_named.c", index * 32 + fault);
            let root = fixture.path().parent().unwrap();
            let message = root.join("message");
            let pin = root.join("context.pin");
            let context = root.join("context");
            let signature = root.join("signature");
            std::fs::write(&message, b"abc").unwrap();
            std::fs::write(&pin, b"1234\n").unwrap();
            std::fs::write(
                &context,
                vec![
                    0xa5;
                    if index == 0 || fault == 24 {
                        0
                    } else if fault == 25 {
                        255
                    } else {
                        3
                    }
                ],
            )
            .unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
                .arg("--module")
                .arg(fixture.path())
                .args([
                    "sign-eddsa-named",
                    "--object",
                    "pkcs11:token=cmac;id=%01;type=private",
                    "--scheme",
                    scheme,
                    "--input",
                ])
                .arg(&message)
                .arg("--context-file")
                .arg(&context)
                .arg("--context-pin-file")
                .arg(&pin)
                .args(["--output", "-"])
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                [0, 25].contains(&fault),
                "{scheme}/{fault}: {output:?}"
            );
            if output.status.success() {
                assert_eq!(output.stdout, vec![0xab; length]);
            } else {
                assert!(output.stdout.is_empty());
            }
            if [23, 24].contains(&fault) {
                let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
                    .arg("--module")
                    .arg(fixture.path())
                    .args([
                        "sign-eddsa-named",
                        "--object",
                        "pkcs11:token=cmac;id=%01;type=private",
                        "--scheme",
                        scheme,
                        "--input",
                    ])
                    .arg(&message)
                    .arg("--context-file")
                    .arg(&context)
                    .arg("--context-pin-file")
                    .arg(&pin)
                    .arg("--output")
                    .arg(&signature)
                    .output()
                    .unwrap();
                assert!(!output.status.success());
                assert!(!signature.exists());
                assert!(output.stdout.is_empty());
            }
        }
        for fault in [0, 1, 3, 8, 9, 10, 11, 13, 15, 16, 17, 19, 20, 21, 23, 24] {
            let fixture = MetadataModule::from_source("eddsa_named.c", index * 32 + fault);
            let root = fixture.path().parent().unwrap();
            let message = root.join("message");
            let context = root.join("context");
            let signature = root.join("signature");
            std::fs::write(&message, b"abc").unwrap();
            std::fs::write(
                &context,
                vec![0xa5; if index == 0 || fault == 24 { 0 } else { 3 }],
            )
            .unwrap();
            std::fs::write(&signature, vec![0xab; length]).unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
                .arg("--module")
                .arg(fixture.path())
                .args([
                    "--format",
                    "json",
                    "verify-eddsa-named",
                    "--object",
                    "pkcs11:token=cmac;id=%01;type=public",
                    "--scheme",
                    scheme,
                    "--input",
                ])
                .arg(&message)
                .arg("--context-file")
                .arg(&context)
                .arg("--signature")
                .arg(&signature)
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                fault == 0,
                "verify {scheme}/{fault}: {output:?}"
            );
            if !output.status.success() {
                assert!(output.stdout.is_empty());
            }
        }
    }
}
#[test]
fn named_cli_rejects_invalid_contexts_profiles_and_inputs_before_loading() {
    let fixture = MetadataModule::from_source("eddsa_named.c", 0);
    let root = fixture.path().parent().unwrap();
    let context = root.join("context");
    let signature = root.join("signature");
    std::fs::write(&context, [0; 256]).unwrap();
    std::fs::write(&signature, [0; 64]).unwrap();
    for (scheme, path) in [("ed25519ctx", context.to_str().unwrap()), ("ed25519", "-")] {
        let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args([
                "--module",
                "/missing-eddsa-module.so",
                "sign-eddsa-named",
                "--object",
                "pkcs11:token=test;id=%01;type=private",
                "--scheme",
                scheme,
                "--input",
                signature.to_str().unwrap(),
                "--context-file",
                path,
                "--output",
                "-",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty());
    }
    std::fs::write(&context, [0; 1]).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .args([
            "--module",
            "/missing-eddsa-module.so",
            "sign-eddsa-named",
            "--object",
            "pkcs11:token=test;id=%01;type=private",
            "--scheme",
            "ed25519",
            "--input",
            signature.to_str().unwrap(),
            "--context-file",
            context.to_str().unwrap(),
            "--output",
            "-",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    for kind in ["edwards25519", "edwards448"] {
        let length = if kind == "edwards25519" { 32 } else { 57 };
        for (bytes, code) in [(vec![0; length], 4), (vec![0; length + 1], 2)] {
            let mut child = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
                .args([
                    "--module",
                    "/missing-eddsa-module.so",
                    "import",
                    "--token",
                    "pkcs11:token=test",
                    "--kind",
                    kind,
                    "--id",
                    "02",
                    "--label",
                    "test",
                    "--input",
                    "-",
                    "--confirm",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(&bytes).unwrap();
            let output = child.wait_with_output().unwrap();
            assert_eq!(output.status.code(), Some(code), "{output:?}");
            assert!(output.stdout.is_empty());
        }
    }
    let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .args([
            "--module",
            "/missing-eddsa-module.so",
            "verify-eddsa-named",
            "--object",
            "pkcs11:token=test;id=%01;type=public",
            "--scheme",
            "ed25519ph",
            "--input",
            "-",
            "--signature",
            "-",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}
