// SPDX-License-Identifier: MIT OR Apache-2.0
//! Structural JSON inspection, opaque IDs and output withheld on cleanup errors.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use serde_json::Value;
use std::process::Command;

#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn template_metadata_softhsm_native_constraints_and_empty_templates() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = std::path::PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let fixtures = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pkcs11-runtime/tests/fixtures");
    let setup = root.join("template-metadata-setup");
    let output = Command::new("cc")
        .args(["-std=c99", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(fixtures.join("headers/2.40"))
        .arg(fixtures.join("template_metadata_setup.c"))
        .arg("-o")
        .arg(&setup)
        .args(if cfg!(target_os = "macos") {
            &[][..]
        } else {
            &["-ldl"][..]
        })
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let module = std::env::var_os("PKCS11_TEST_MODULE").unwrap();
    let output = Command::new(setup).arg(&module).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let pin = root.join("template-metadata.pin");
    std::fs::write(&pin, b"12345678\n").unwrap();
    for kind in ["wrap", "unwrap", "derive"] {
        let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .arg("--module")
            .arg(&module)
            .args([
                "--format",
                "json",
                "template-metadata",
                "--object",
                "pkcs11:token=client-test;id=%D8%54%4D;type=secret-key",
                "--template",
                kind,
                "--pin-file",
            ])
            .arg(&pin)
            .output()
            .unwrap();
        assert!(output.status.success(), "{kind}: {output:?}");
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let result = &value["result"];
        if kind == "derive" {
            assert_eq!(result["status"], "unsupported");
        } else {
            assert_eq!(result["status"], "available");
            let members = result["members"].as_array().unwrap();
            assert_eq!(members.len(), if kind == "wrap" { 2 } else { 0 });
            for member in members {
                assert_eq!(member["status"], "available");
                assert_eq!(member["length"], 1);
                assert!(member.get("value").is_none());
            }
        }
    }
}

#[test]
fn template_metadata_cli_reports_structure_statuses_and_native_failures() {
    for kind in ["wrap", "unwrap", "derive"] {
        for fault in [0, 1, 2, 3, 4, 8, 12, 17, 22, 23, 24, 30, 31] {
            let fixture = MetadataModule::from_source("template_metadata.c", fault);
            let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
                .arg("--module")
                .arg(fixture.path())
                .args([
                    "--format",
                    "json",
                    "template-metadata",
                    "--object",
                    "pkcs11:token=cmac;id=%01;type=secret-key",
                    "--template",
                    kind,
                ])
                .output()
                .unwrap();
            if [8, 12, 17, 30, 31].contains(&fault) {
                assert_eq!(output.status.code(), Some(5), "{kind}/{fault}: {output:?}");
                assert!(output.stdout.is_empty());
                continue;
            }
            assert!(output.status.success(), "{kind}/{fault}: {output:?}");
            assert!(output.stderr.is_empty());
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            let result = &value["result"];
            assert_eq!(
                result["attribute_type"],
                match kind {
                    "wrap" => "0x40000211",
                    "unwrap" => "0x40000212",
                    _ => "0x40000213",
                }
            );
            assert_eq!(
                result["status"],
                match fault {
                    2 => "sensitive",
                    3 => "unsupported",
                    4 => "unavailable",
                    _ => "available",
                }
            );
            let members = result["members"].as_array().unwrap();
            assert_eq!(
                members.len(),
                if [1, 2, 3, 4].contains(&fault) { 0 } else { 8 }
            );
            if !members.is_empty() {
                assert_eq!(members[1]["attribute_type"], "0x11");
                assert_eq!(members[1]["length"], 32);
                assert!(members[1].get("value").is_none());
                assert_eq!(members[5]["members"].as_array().unwrap().len(), 2);
                assert_eq!(members[6]["status"], "unavailable");
                assert!(members[7]["members"].as_array().unwrap().is_empty());
            }
        }
    }
}
