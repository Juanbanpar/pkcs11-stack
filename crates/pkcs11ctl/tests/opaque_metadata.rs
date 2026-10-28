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
