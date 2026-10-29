// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit X25519 workflows, preflight validation and checked output release.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
#[path = "../../pkcs11-runtime/tests/fixtures/x25519_vectors.rs"]
#[allow(dead_code)]
mod vectors;
use metadata_module::MetadataModule;
use serde_json::Value;
use std::process::{Command, Stdio};

#[test]
fn native_x25519_derivation_and_export_fail_closed_through_cleanup() {
    for fault in [
        0, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 27,
    ] {
        let fixture = MetadataModule::from_source("x25519.c", fault);
        let input = fixture.path().parent().unwrap().join("peer.der");
        let mut public = [0; 32];
        public[0] = 9;
        std::fs::write(&input, vectors::spki(&public)).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .arg("--module")
            .arg(fixture.path())
            .args([
                "--format",
                "json",
                "derive-x25519",
                "--object",
                "pkcs11:token=cmac;id=%01;type=private",
                "--id",
                "02",
                "--label",
                "shared",
                "--confirm",
                "--input",
            ])
            .arg(input)
            .output()
            .unwrap();
        if [0, 26].contains(&fault) {
            assert!(output.status.success(), "fault {fault}: {output:?}");
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["result"]["length"], 32);
            assert_eq!(result["result"]["extractable"], false);
        } else {
            assert!(!output.status.success(), "fault {fault}");
            assert!(output.stdout.is_empty());
            if [15, 16, 17, 22, 23, 24].contains(&fault) {
                assert_eq!(output.status.code(), Some(5), "fault {fault}");
            }
        }
    }
    for fault in [0, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 23, 24] {
        let fixture = MetadataModule::from_source("x25519.c", fault);
        let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .arg("--module")
            .arg(fixture.path())
            .args([
                "--format",
                "json",
                "export",
                "--object",
                "pkcs11:token=cmac;id=%01;type=public",
                "--key-family",
                "x25519",
                "--output",
                "-",
            ])
            .output()
            .unwrap();
        if fault == 0 {
            let mut public = [0; 32];
            public[0] = 9;
            assert_eq!(output.stdout, vectors::spki(&public));
            assert!(output.status.success());
        } else {
            assert!(!output.status.success(), "fault {fault}");
            assert!(output.stdout.is_empty());
        }
    }
}
#[test]
fn malformed_peer_input_is_rejected_before_module_loading() {
    use std::io::Write;
    for (bytes, code) in [
        (vectors::spki(&[0; 32]), 4),
        (vec![0; 129], 2),
        (vectors::hex("302c300706032b656e0500032100"), 4),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args([
                "--module",
                "/missing-x25519-module.so",
                "--format",
                "json",
                "derive-x25519",
                "--object",
                "pkcs11:token=test;id=%01;type=private",
                "--id",
                "02",
                "--label",
                "shared",
                "--confirm",
                "--input",
                "-",
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

#[test]
fn native_generation_and_import_withhold_results_through_cleanup_failures() {
    let mut public = [0; 32];
    public[0] = 9;
    for generate in [true, false] {
        for fault in 0..=15 {
            let fixture = MetadataModule::from_source("x25519_management.c", fault);
            let input = fixture.path().parent().unwrap().join("public.der");
            std::fs::write(&input, vectors::spki(&public)).unwrap();
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
            cmd.arg("--module").arg(fixture.path()).args([
                "--format",
                "json",
                if generate { "generate" } else { "import" },
                "--token",
                "pkcs11:token=cmac",
                "--kind",
                "x25519",
                "--id",
                "02",
                "--label",
                "X25519",
                "--confirm",
            ]);
            if !generate {
                cmd.arg("--input").arg(&input);
            }
            let output = cmd.output().unwrap();
            let fail = if generate {
                [1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15].contains(&fault)
            } else {
                [7, 8, 9, 12, 13, 14].contains(&fault)
            };
            assert_eq!(
                !output.status.success(),
                fail,
                "{generate}/{fault}: {output:?}"
            );
            if fail {
                assert!(output.stdout.is_empty());
            } else {
                let result: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(result["result"]["key"]["type"], "x25519");
                assert_eq!(result["result"]["key"]["bits"], 255);
                if generate {
                    assert_eq!(result["result"]["extractable"], false);
                }
            }
        }
    }
}

#[test]
fn x25519_management_rejects_invalid_options_and_input_before_loading_module() {
    use std::io::Write;
    for extra in [
        vec!["--always-authenticate"],
        vec!["--purpose", "signing"],
        vec!["--bits", "256"],
        vec!["--general-tag"],
        vec!["--id", ""],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args([
                "--module",
                "/missing-x25519-module.so",
                "generate",
                "--token",
                "pkcs11:token=test",
                "--kind",
                "x25519",
                "--id",
                "02",
                "--label",
                "X25519",
                "--confirm",
            ])
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty());
    }
    for (bytes, code) in [
        (vectors::spki(&[0; 32]), 4),
        (vec![0; 129], 2),
        (vectors::hex("302c300706032b656e0500032100"), 4),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args([
                "--module",
                "/missing-x25519-module.so",
                "import",
                "--token",
                "pkcs11:token=test",
                "--kind",
                "x25519",
                "--id",
                "02",
                "--label",
                "X25519",
                "--confirm",
                "--input",
                "-",
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
