// SPDX-License-Identifier: MIT OR Apache-2.0
//! Raw curveName CLI validation and checked result release through native failures.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use serde_json::Value;
use std::{
    io::Write,
    process::{Command, Stdio},
};
fn raw(length: usize, base: u8) -> Vec<u8> {
    let mut bytes = vec![0; length];
    bytes[0] = base;
    bytes
}
#[test]
fn native_named_agreement_and_export_withhold_results_on_provider_and_cleanup_errors() {
    for (curve, length, base) in [("curve25519", 32, 9), ("curve448", 56, 5)] {
        for fault in [
            0, 1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 27,
        ] {
            let fixture = MetadataModule::from_source(&format!("{curve}.c"), fault);
            let input = fixture.path().parent().unwrap().join("peer.raw");
            std::fs::write(&input, raw(length, base)).unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
                .arg("--module")
                .arg(fixture.path())
                .args([
                    "--format",
                    "json",
                    "derive-montgomery",
                    "--object",
                    "pkcs11:token=cmac;id=%01;type=private",
                    "--curve",
                    curve,
                    "--input",
                ])
                .arg(&input)
                .args(["--id", "02", "--label", "shared", "--confirm"])
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                [0, 26].contains(&fault),
                "{curve}/{fault}: {output:?}"
            );
            if output.status.success() {
                let result: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(result["result"]["length"], length);
                assert_eq!(result["result"]["curve"], curve);
                assert_eq!(result["result"]["extractable"], false);
            } else {
                assert!(output.stdout.is_empty());
            }
        }
        for fault in [0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 23, 24] {
            let fixture = MetadataModule::from_source(&format!("{curve}.c"), fault);
            let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
                .arg("--module")
                .arg(fixture.path())
                .args([
                    "export",
                    "--object",
                    "pkcs11:token=cmac;id=%01;type=public",
                    "--key-family",
                    curve,
                    "--output",
                    "-",
                ])
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                fault == 0,
                "{curve}/{fault}: {output:?}"
            );
            if fault == 0 {
                assert_eq!(output.stdout, raw(length, base));
            } else {
                assert!(output.stdout.is_empty());
            }
            if [23, 24].contains(&fault) {
                let path = fixture.path().parent().unwrap().join("failed.raw");
                let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
                    .arg("--module")
                    .arg(fixture.path())
                    .args([
                        "export",
                        "--object",
                        "pkcs11:token=cmac;id=%01;type=public",
                        "--key-family",
                        curve,
                        "--output",
                    ])
                    .arg(&path)
                    .output()
                    .unwrap();
                assert!(!output.status.success());
                assert!(!path.exists());
                assert!(output.stdout.is_empty());
            }
        }
    }
}
#[test]
fn native_named_generation_and_import_enforce_templates_and_checked_cleanup() {
    for (curve, length, base, bits) in [("curve25519", 32, 9, 255), ("curve448", 56, 5, 448)] {
        for generate in [true, false] {
            for fault in 0..=15 {
                let fixture = MetadataModule::from_source(&format!("{curve}_management.c"), fault);
                let input = fixture.path().parent().unwrap().join("public.raw");
                std::fs::write(&input, raw(length, base)).unwrap();
                let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
                command.arg("--module").arg(fixture.path()).args([
                    "--format",
                    "json",
                    if generate { "generate" } else { "import" },
                    "--token",
                    "pkcs11:token=cmac",
                    "--kind",
                    curve,
                    "--id",
                    "02",
                    "--label",
                    curve,
                    "--confirm",
                ]);
                if !generate {
                    command.arg("--input").arg(&input);
                }
                let output = command.output().unwrap();
                let fail = if generate {
                    [1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15].contains(&fault)
                } else {
                    [7, 8, 9, 12, 13, 14].contains(&fault)
                };
                assert_eq!(
                    !output.status.success(),
                    fail,
                    "{curve}/{generate}/{fault}: {output:?}"
                );
                if fail {
                    assert!(output.stdout.is_empty());
                } else {
                    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
                    assert_eq!(result["result"]["key"]["type"], curve);
                    assert_eq!(result["result"]["key"]["bits"], bits);
                }
            }
        }
    }
}
fn missing_module(args: &[&str], bytes: Option<&[u8]>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
    command
        .args(["--module", "/missing-named-module.so", "--format", "json"])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if bytes.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().unwrap();
    if let Some(bytes) = bytes {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    }
    child.wait_with_output().unwrap()
}
#[test]
fn malformed_raw_peers_and_invalid_generation_options_fail_before_module_loading() {
    for (curve, length, base) in [("curve25519", 32, 9), ("curve448", 56, 5)] {
        for import in [true, false] {
            for (bytes, code) in [
                (vec![], 4),
                (vec![0; length], 4),
                (raw(length - 1, base), 4),
                (raw(length + 1, base), 2),
                (
                    {
                        let mut wrapped = vec![4, length as u8];
                        wrapped.extend(raw(length, base));
                        wrapped
                    },
                    2,
                ),
            ] {
                let mut args = if import {
                    vec!["import", "--token", "pkcs11:token=test", "--kind", curve]
                } else {
                    vec![
                        "derive-montgomery",
                        "--object",
                        "pkcs11:token=test;id=%01;type=private",
                        "--curve",
                        curve,
                    ]
                };
                args.extend([
                    "--input",
                    "-",
                    "--id",
                    "02",
                    "--label",
                    "shared",
                    "--confirm",
                ]);
                let output = missing_module(&args, Some(&bytes));
                assert_eq!(
                    output.status.code(),
                    Some(code),
                    "{curve}/{import}: {output:?}"
                );
                assert!(output.stdout.is_empty());
            }
        }
        for extra in [
            vec!["--always-authenticate"],
            vec!["--purpose", "signing"],
            vec!["--bits", "255"],
            vec!["--general-tag"],
            vec!["--id", ""],
            vec!["--label", ""],
        ] {
            let mut args = vec![
                "generate",
                "--token",
                "pkcs11:token=test",
                "--kind",
                curve,
                "--id",
                "02",
                "--label",
                curve,
                "--confirm",
            ];
            args.extend(extra);
            let output = missing_module(&args, None);
            assert_eq!(output.status.code(), Some(2), "{output:?}");
            assert!(output.stdout.is_empty());
        }
        let output = missing_module(
            &[
                "export",
                "--object",
                "pkcs11:token=test;id=%01;type=private",
                "--key-family",
                curve,
                "--output",
                "-",
            ],
            None,
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let output = missing_module(
            &[
                "derive-montgomery",
                "--object",
                "pkcs11:token=test;id=%01;type=public",
                "--curve",
                curve,
                "--input",
                "-",
                "--id",
                "02",
                "--label",
                "shared",
                "--confirm",
            ],
            Some(&raw(length, base)),
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}
