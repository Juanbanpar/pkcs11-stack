// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit X448 workflows, preflight validation and checked output release.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
#[path = "../../pkcs11-runtime/tests/fixtures/x448_vectors.rs"]
#[allow(dead_code)]
mod vectors;
use metadata_module::MetadataModule;
use serde_json::Value;
use std::process::{Command, Stdio};

#[test]
fn native_x448_derivation_and_export_fail_closed_through_cleanup() {
    for fault in [
        0, 1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 27, 28,
    ] {
        let fixture = MetadataModule::from_source("x448.c", fault);
        let input = fixture.path().parent().unwrap().join("peer.der");
        let mut public = [0; 56];
        public[0] = 5;
        std::fs::write(&input, vectors::spki(&public)).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .arg("--module")
            .arg(fixture.path())
            .args([
                "--format",
                "json",
                "derive-x448",
                "--kdf",
                "null",
                "--kind",
                "raw-secret",
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
            assert_eq!(result["result"]["length"], 56);
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
        let fixture = MetadataModule::from_source("x448.c", fault);
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
                "x448",
                "--output",
                "-",
            ])
            .output()
            .unwrap();
        if fault == 0 {
            let mut public = [0; 56];
            public[0] = 5;
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
        (vectors::spki(&[0; 56]), 4),
        (vec![0; 129], 2),
        (vectors::hex("3044300706032b656f0500033900"), 4),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args([
                "--module",
                "/missing-x448-module.so",
                "--format",
                "json",
                "derive-x448",
                "--kdf",
                "null",
                "--kind",
                "raw-secret",
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
fn explicit_sha512_profiles_preserve_checked_output_and_reject_invalid_combinations() {
    use std::io::Write;
    let mut public = [0; 56];
    public[0] = 5;
    for (profile, kdf, kind, length) in [
        (1, "x963-sha512", "secret", 64),
        (2, "nist-sha512", "aes256", 32),
    ] {
        for fault in [0, 22, 23, 24] {
            let fixture = MetadataModule::from_source("x448.c", 40 * profile + fault);
            let input = fixture.path().parent().unwrap().join("peer.der");
            std::fs::write(&input, vectors::spki(&public)).unwrap();
            let context = fixture.path().parent().unwrap().join("context");
            std::fs::write(&context, b"context").unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
                .arg("--module")
                .arg(fixture.path())
                .args([
                    "--format",
                    "json",
                    "derive-x448",
                    "--object",
                    "pkcs11:token=cmac;id=%01;type=private",
                    "--kdf",
                    kdf,
                    "--kind",
                    kind,
                    "--id",
                    "02",
                    "--label",
                    "shared",
                    "--confirm",
                    "--input",
                ])
                .arg(input)
                .arg("--shared-info-file")
                .arg(context)
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                fault == 0,
                "{profile}/{fault}: {output:?}"
            );
            if fault == 0 {
                let value: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(value["result"]["length"], length);
                assert_eq!(value["result"]["extractable"], false);
            } else {
                assert!(output.stdout.is_empty());
                assert_eq!(output.status.code(), Some(5));
            }
        }
    }
    for (kdf, kind) in [
        ("null", "secret"),
        ("null", "aes256"),
        ("x963-sha512", "raw-secret"),
        ("nist-sha512", "raw-secret"),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args([
                "--module",
                "/missing-x448-module.so",
                "--format",
                "json",
                "derive-x448",
                "--object",
                "pkcs11:token=test;id=%01;type=private",
                "--kdf",
                kdf,
                "--kind",
                kind,
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
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&vectors::spki(&public))
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn native_generation_and_import_withhold_results_through_cleanup_failures() {
    let mut public = [0; 56];
    public[0] = 5;
    for generate in [true, false] {
        for fault in 0..=15 {
            let fixture = MetadataModule::from_source("x448_management.c", fault);
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
                "x448",
                "--id",
                "02",
                "--label",
                "X448",
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
                assert_eq!(result["result"]["key"]["type"], "x448");
                assert_eq!(result["result"]["key"]["bits"], 448);
                if generate {
                    assert_eq!(result["result"]["extractable"], false);
                }
            }
        }
    }
}

#[test]
fn x448_management_rejects_invalid_options_and_input_before_loading_module() {
    use std::io::Write;
    let oversized_id = "ab".repeat(129);
    let oversized_label = "x".repeat(129);
    for (id, label) in [
        ("", "X448"),
        (oversized_id.as_str(), "X448"),
        ("02", ""),
        ("02", oversized_label.as_str()),
    ] {
        for generate in [true, false] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
            command.args([
                "--module",
                "/missing-x448-module.so",
                if generate { "generate" } else { "import" },
                "--token",
                "pkcs11:token=test",
                "--kind",
                "x448",
                "--id",
                id,
                "--label",
                label,
                "--confirm",
            ]);
            if !generate {
                command.args(["--input", "-"]);
            }
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            if !generate {
                let mut public = [0; 56];
                public[0] = 5;
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(&vectors::spki(&public))
                    .unwrap();
            }
            let output = child.wait_with_output().unwrap();
            assert_eq!(output.status.code(), Some(2), "{output:?}");
            assert!(output.stdout.is_empty());
        }
    }
    for extra in [
        vec!["--always-authenticate"],
        vec!["--purpose", "signing"],
        vec!["--bits", "256"],
        vec!["--general-tag"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args([
                "--module",
                "/missing-x448-module.so",
                "generate",
                "--token",
                "pkcs11:token=test",
                "--kind",
                "x448",
                "--id",
                "02",
                "--label",
                "X448",
                "--confirm",
            ])
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty());
    }
    for (bytes, code) in [
        (vectors::spki(&[0; 56]), 4),
        (vec![0; 129], 2),
        (vectors::hex("3044300706032b656f0500033900"), 4),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args([
                "--module",
                "/missing-x448-module.so",
                "import",
                "--token",
                "pkcs11:token=test",
                "--kind",
                "x448",
                "--id",
                "02",
                "--label",
                "X448",
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
