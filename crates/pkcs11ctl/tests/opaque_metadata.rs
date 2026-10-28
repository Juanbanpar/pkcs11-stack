// SPDX-License-Identifier: MIT OR Apache-2.0
//! Opaque object/key types survive CLI inspection without enabling typed export.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
mod metadata_module;
use metadata_module::MetadataModule;
use serde_json::Value;
use std::process::Command;

#[test]
fn mixed_object_listing_and_key_inspection_preserve_numeric_ids() {
    for fault in 0..=2 {
        let fixture = MetadataModule::new(fault);
        let raw = match fault {
            0 => 0x7fff0001,
            1 => 0x80000001,
            _ => std::os::raw::c_ulong::MAX,
        };
        let run = |args: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
                .arg("--module")
                .arg(fixture.path())
                .args(["--format", "json"])
                .args(args)
                .output()
                .unwrap()
        };
        let output = run(&["objects", "--token", "pkcs11:token=cmac"]);
        assert!(output.status.success(), "{:?}", output);
        let listing: Value = serde_json::from_slice(&output.stdout).unwrap();
        let objects = listing["result"].as_array().unwrap();
        assert_eq!(objects.len(), 8);
        assert!(objects[0]["uri"].is_null());
        assert_eq!(
            objects[0]["attributes"]["class"]["value"],
            format!("ObjectClass {{ val: {raw} }}")
        );
        assert_eq!(objects[5]["attributes"]["class"]["value"], "data");
        assert!(objects[5]["uri"].as_str().unwrap().contains("type=data"));
        let uri = "pkcs11:token=cmac;id=%03;type=public";
        let output = run(&["inspect", "--object", uri, "--attributes", "key-type"]);
        assert!(output.status.success(), "{:?}", output);
        let inspection: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(inspection["result"]["key-type"]["status"], "available");
        assert_eq!(
            inspection["result"]["key-type"]["value"],
            format!("KeyType {{ val: {raw} }}")
        );
        let output = run(&["export", "--object", uri, "--output", "-"]);
        assert_eq!(output.status.code(), Some(4), "{:?}", output);
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn public_metadata_cli_preserves_optional_status_and_selector_semantics() {
    for fault in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] {
        let fixture = MetadataModule::from_source("public_metadata.c", fault);
        let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .arg("--module")
            .arg(fixture.path())
            .args([
                "--format",
                "json",
                "public-metadata",
                "--token",
                "pkcs11:token=cmac",
            ])
            .output()
            .unwrap();
        if fault >= 5 {
            assert!(!output.status.success(), "fault {fault}: {output:?}");
            assert!(output.stdout.is_empty());
            continue;
        }
        assert!(output.status.success(), "{output:?}");
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let rows = value["result"].as_array().unwrap();
        assert_eq!(rows.len(), 8);
        assert!(rows[6]["uri"].is_null());
        assert!(rows[7]["uri"].is_null());
        assert_eq!(rows[6]["trust_validated"], false);
        assert_eq!(
            rows[6]["attributes"]["unique-id"]["status"],
            match fault {
                2 => "sensitive",
                3 => "unsupported",
                4 => "unavailable",
                _ => "available",
            }
        );
        if fault == 0 {
            assert_eq!(rows[6]["attributes"]["validation-version"]["value"], "3.2");
            assert_eq!(
                rows[6]["attributes"]["validation-flag"]["value"],
                "0x80000001"
            );
            assert_eq!(
                rows[6]["attributes"]["validation-vendor-uri"]["value"]["text"],
                "https://validation.invalid/untrusted"
            );
            assert_eq!(
                rows[7]["attributes"]["profile-id"]["value"]["id"],
                "0x7fff0001"
            );
            assert!(rows[2]["uri"].as_str().unwrap().contains("id=%03"));
        }
        if fault == 1 {
            assert_eq!(rows[6]["attributes"]["unique-id"]["value"]["hex"], "");
        }
    }
}

#[test]
fn session_validation_cli_marks_fresh_session_and_reports_unavailable() {
    for fault in 0..=9 {
        let fixture = MetadataModule::from_source("session_validation.c", fault);
        let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .arg("--module")
            .arg(fixture.path())
            .args([
                "--format",
                "json",
                "session-validation",
                "--token",
                "pkcs11:token=cmac",
            ])
            .output()
            .unwrap();
        if matches!(fault, 3 | 7) {
            assert_eq!(output.status.code(), Some(5));
            assert!(output.stdout.is_empty());
            continue;
        }
        assert!(output.status.success(), "{output:?}");
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["result"]["fresh_session"], true);
        assert_eq!(value["result"]["trust_validated"], false);
        let unavailable = matches!(fault, 1 | 2 | 6 | 8 | 9);
        assert_eq!(
            value["result"]["status"],
            if unavailable {
                "unavailable"
            } else {
                "available"
            }
        );
        assert_eq!(
            value["result"]["flags"],
            if unavailable {
                Value::Null
            } else {
                Value::String("0x0".into())
            }
        );
    }
}
