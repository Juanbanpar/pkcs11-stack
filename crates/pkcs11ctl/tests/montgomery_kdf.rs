// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native CLI profiles, invalid parameter preflight and checked result release.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use std::process::{Command, Output};
fn invoke(
    module: &std::path::Path,
    peer: &std::path::Path,
    info: &std::path::Path,
    curve: usize,
    extra: &[&str],
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
    cmd.arg("--module")
        .arg(module)
        .args([
            "--format",
            "json",
            match curve {
                0 => "derive-x25519",
                1 => "derive-x448",
                _ => "derive-montgomery",
            },
            "--object",
            "pkcs11:token=cmac;id=%01;type=private",
            "--id",
            "02",
            "--label",
            "shared",
            "--confirm",
        ])
        .arg("--input")
        .arg(peer)
        .arg("--shared-info-file")
        .arg(info)
        .args(extra);
    if curve >= 2 {
        cmd.args([
            "--curve",
            if curve == 2 { "curve25519" } else { "curve448" },
        ]);
    }
    cmd.output().unwrap()
}
fn peer(curve: usize) -> Vec<u8> {
    let mut bytes = vec![0; if curve % 2 == 0 { 32 } else { 56 }];
    bytes[0] = if curve % 2 == 0 { 9 } else { 5 };
    if curve < 2 {
        let mut spki = if curve == 0 {
            vec![0x30, 0x2a, 0x30, 5, 6, 3, 43, 101, 110, 3, 33, 0]
        } else {
            vec![0x30, 0x42, 0x30, 5, 6, 3, 43, 101, 111, 3, 57, 0]
        };
        spki.extend(bytes);
        spki
    } else {
        bytes
    }
}
#[test]
fn explicit_kdfs_keep_native_parameters_and_withhold_output_on_cleanup_errors() {
    let kdfs = [
        "x963-sha224",
        "x963-sha256",
        "x963-sha384",
        "x963-sha512",
        "nist-sha224",
        "nist-sha256",
        "nist-sha384",
        "nist-sha512",
    ];
    for curve in 0..4 {
        for (kdf, name) in kdfs.iter().enumerate() {
            for output in [1, 5] {
                let faults: &[usize] = if kdf == 1 && output == 5 {
                    &[0, 3, 9, 14, 15, 17, 20, 21, 22, 23, 24, 27]
                } else {
                    &[0]
                };
                for fault in faults {
                    let fixture = MetadataModule::with_case(
                        "montgomery_kdf.c",
                        40 * (curve * 48 + kdf * 6 + output) + fault,
                        "3.2",
                    );
                    let root = fixture.path().parent().unwrap();
                    let input = root.join("peer");
                    let info = root.join("info");
                    std::fs::write(&input, peer(curve)).unwrap();
                    std::fs::write(
                        &info,
                        if output == 1 {
                            b"".as_slice()
                        } else {
                            b"context\0"
                        },
                    )
                    .unwrap();
                    let mut extra = vec![
                        "--kdf",
                        name,
                        "--kind",
                        if output == 1 {
                            "derivation-secret"
                        } else {
                            "aes256"
                        },
                    ];
                    if output == 1 {
                        extra.extend(["--length", "64"]);
                    }
                    let result = invoke(fixture.path(), &input, &info, curve, &extra);
                    assert_eq!(
                        result.status.success(),
                        *fault == 0,
                        "{curve}/{kdf}/{output}/{fault}: {result:?}"
                    );
                    if *fault == 0 {
                        let value: serde_json::Value =
                            serde_json::from_slice(&result.stdout).unwrap();
                        assert_eq!(value["result"]["length"], if output == 1 { 64 } else { 32 });
                        assert_eq!(value["result"]["extractable"], false);
                    } else {
                        assert!(result.stdout.is_empty());
                        if [15, 17, 22, 23, 24].contains(fault) {
                            assert_eq!(result.status.code(), Some(5));
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn inconsistent_kdfs_lengths_and_context_are_rejected_before_module_loading() {
    let fixture = MetadataModule::from_source("x25519.c", 0);
    let root = fixture.path().parent().unwrap();
    let input = root.join("peer");
    let info = root.join("info");
    for curve in 0..4 {
        std::fs::write(&input, peer(curve)).unwrap();
        std::fs::write(&info, b"").unwrap();
        for extra in [
            vec!["--kdf", "null", "--kind", "aes256"],
            vec!["--kdf", "nist-sha256", "--kind", "raw-secret"],
            vec!["--kdf", "x963-sha384", "--kind", "derivation-secret"],
            vec![
                "--kdf",
                "x963-sha256",
                "--kind",
                "derivation-secret",
                "--length",
                "0",
            ],
            vec![
                "--kdf",
                "nist-sha512",
                "--kind",
                "derivation-secret",
                "--length",
                "4097",
            ],
            vec![
                "--kdf",
                "nist-sha512",
                "--kind",
                "derivation-secret",
                "--length",
                "18446744073709551615",
            ],
            vec!["--kdf", "null", "--kind", "raw-secret", "--length", "32"],
            vec!["--kdf", "x963-sha224", "--kind", "aes128", "--length", "16"],
        ] {
            let result = invoke(
                std::path::Path::new("/missing"),
                &input,
                &info,
                curve,
                &extra,
            );
            assert_eq!(
                result.status.code(),
                Some(2),
                "{curve}/{extra:?}: {result:?}"
            );
            assert!(result.stdout.is_empty());
        }
        let result = invoke(
            std::path::Path::new("/missing"),
            &input,
            std::path::Path::new("-"),
            curve,
            &["--kdf", "nist-sha256", "--kind", "aes256"],
        );
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        for context in [vec![0; 1], vec![0; 4097]] {
            std::fs::write(&info, context).unwrap();
            let result = invoke(
                std::path::Path::new("/missing"),
                &input,
                &info,
                curve,
                &["--kdf", "null", "--kind", "raw-secret"],
            );
            assert_eq!(result.status.code(), Some(2));
            assert!(result.stdout.is_empty());
        }
    }
}
