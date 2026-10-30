// SPDX-License-Identifier: MIT OR Apache-2.0
//! AES-CMAC PRF selection, IV preflight and cleanup-gated CLI results.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/kbkdf_cmac_module.rs"]
mod fixture;
use fixture::KbkdfCmacModule;
use std::process::{Command, Output};
fn run(
    module: &std::path::Path,
    mode: &str,
    iv: Option<&std::path::Path>,
    extra: &[&str],
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
    command.arg("--module").arg(module).args([
        "--format",
        "json",
        "derive-kbkdf",
        "--object",
        "pkcs11:token=cmac;id=%01;type=secret-key",
        "--prf",
        "aes-cmac",
        "--mode",
        mode,
        "--kind",
        "aes256",
        "--id",
        "03",
        "--label",
        "CMAC output",
        "--confirm",
    ]);
    if let Some(iv) = iv {
        command.arg("--kdf-iv-file").arg(iv);
    }
    command.args(extra).output().unwrap()
}
#[test]
fn all_modes_and_aes_sizes_report_cmac_without_a_digest() {
    for (fault, mode) in [(0, "counter"), (20, "feedback"), (40, "double-pipeline")] {
        for length in [16, 24, 32] {
            let fixture = KbkdfCmacModule::new(3, 2, fault, length);
            let out = run(&fixture.path(), mode, None, &[]);
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(value["result"]["prf"], "aes-cmac");
            assert!(value["result"].get("digest").is_none());
            let out = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
                .arg("--module")
                .arg(fixture.path())
                .args([
                    "--format",
                    "json",
                    "kbkdf-capabilities",
                    "--object",
                    "pkcs11:token=cmac;id=%01;type=secret-key",
                    "--prf",
                    "aes-cmac",
                    "--mode",
                    mode,
                ])
                .output()
                .unwrap();
            assert!(out.status.success());
            let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(value["result"]["input_length"], length);
            assert_eq!(value["result"]["prf_output_length"], 16);
        }
    }
}
#[test]
fn digest_and_wrong_iv_profiles_fail_before_module_loading() {
    let fixture = KbkdfCmacModule::new(3, 2, 0, 32);
    let iv = fixture.path().parent().unwrap().join("iv");
    let missing = std::path::Path::new("/missing");
    assert_eq!(
        run(missing, "counter", None, &["--digest", "sha256"])
            .status
            .code(),
        Some(2)
    );
    for mode in ["counter", "feedback", "double-pipeline"] {
        for length in [0, 1, 15, 16, 17, 32, 64, 65] {
            std::fs::write(&iv, vec![0; length]).unwrap();
            let out = run(missing, mode, Some(&iv), &[]);
            assert_eq!(
                out.status.code(),
                Some(if mode == "feedback" && (length == 0 || length == 16) {
                    5
                } else {
                    2
                })
            );
            assert!(out.stdout.is_empty());
        }
    }
}
#[test]
fn native_derivation_and_cleanup_failures_withhold_success_output() {
    for offset in [0, 20, 40] {
        for fault in [5, 10, 11] {
            let fixture = KbkdfCmacModule::new(3, 2, offset + fault, 32);
            let mode = if offset == 0 {
                "counter"
            } else if offset == 20 {
                "feedback"
            } else {
                "double-pipeline"
            };
            let out = run(&fixture.path(), mode, None, &[]);
            assert_eq!(out.status.code(), Some(5));
            assert!(out.stdout.is_empty());
        }
    }
}
