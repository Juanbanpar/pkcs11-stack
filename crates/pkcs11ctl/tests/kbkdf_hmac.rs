// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit HMAC PRFs, capability compatibility, IV preflight and checked output.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/kbkdf_cmac_module.rs"]
mod fixture;
use fixture::KbkdfCmacModule;
use std::{
    path::Path,
    process::{Command, Output},
};
const PROFILES: [(&str, &str, &str, usize); 5] = [
    ("sha224", "CKM_SHA224_HMAC", "CKK_SHA224_HMAC", 28),
    ("sha3-224", "CKM_SHA3_224_HMAC", "CKK_SHA3_224_HMAC", 28),
    ("sha3-256", "CKM_SHA3_256_HMAC", "CKK_SHA3_256_HMAC", 32),
    ("sha3-384", "CKM_SHA3_384_HMAC", "CKK_SHA3_384_HMAC", 48),
    ("sha3-512", "CKM_SHA3_512_HMAC", "CKK_SHA3_512_HMAC", 64),
];
fn run(module: &Path, command: &str, digest: Option<&str>, mode: &str, extra: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
    cmd.arg("--module").arg(module).args([
        "--format",
        "json",
        command,
        "--object",
        "pkcs11:token=cmac;id=%01;type=secret-key",
        "--mode",
        mode,
    ]);
    if command == "derive-kbkdf" {
        cmd.args([
            "--kind",
            "aes256",
            "--id",
            "03",
            "--label",
            "HMAC KDF",
            "--confirm",
        ]);
    }
    if let Some(digest) = digest {
        cmd.args(["--digest", digest]);
    }
    cmd.args(extra).output().unwrap()
}
#[test]
fn explicit_hash_capabilities_and_derivation_select_the_same_native_prf() {
    for (digest, mechanism, typed, length) in PROFILES {
        for (fault, mode) in [(0, "counter"), (20, "feedback"), (40, "double-pipeline")] {
            let fixture = KbkdfCmacModule::hmac(3, 2, fault, mechanism, typed, length);
            for command in ["kbkdf-capabilities", "derive-kbkdf"] {
                let out = run(&fixture.path(), command, Some(digest), mode, &[]);
                assert!(
                    out.status.success(),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                assert_eq!(value["result"]["digest"], digest);
                if command == "kbkdf-capabilities" {
                    assert_eq!(value["result"]["prf"], "hmac");
                    assert_eq!(value["result"]["prf_output_length"], length);
                } else {
                    assert_eq!(value["result"]["derived"], true);
                    assert!(value["result"].get("prf").is_none());
                }
            }
        }
    }
    let fixture = KbkdfCmacModule::hmac(3, 2, 0, "CKM_SHA224_HMAC", "CKK_GENERIC_SECRET", 28);
    let out = run(&fixture.path(), "kbkdf-capabilities", None, "counter", &[]);
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        value["result"]["digests"],
        serde_json::json!(["sha256", "sha384", "sha512"])
    );
    assert!(value["result"].get("digest").is_none());
    assert!(value["result"].get("prf").is_none());
}
#[test]
fn selected_hash_iv_bounds_and_rejected_prf_combinations_precede_loading() {
    for (digest, mechanism, typed, length) in PROFILES {
        let fixture = KbkdfCmacModule::hmac(3, 2, 20, mechanism, typed, length);
        let iv = fixture.path().parent().unwrap().join("iv");
        for n in [0, 1, 27, 28, 29, 31, 32, 33, 47, 48, 49, 63, 64, 65] {
            std::fs::write(&iv, vec![0xA5; n]).unwrap();
            let out = run(
                Path::new("/missing"),
                "derive-kbkdf",
                Some(digest),
                "feedback",
                &["--kdf-iv-file", iv.to_str().unwrap()],
            );
            assert_eq!(
                out.status.code(),
                Some(if n == 0 || n == length { 5 } else { 2 })
            );
            assert!(out.stdout.is_empty());
        }
        for command in ["kbkdf-capabilities", "derive-kbkdf"] {
            let out = run(
                Path::new("/missing"),
                command,
                Some(digest),
                "counter",
                &["--prf", "aes-cmac"],
            );
            assert_eq!(out.status.code(), Some(2));
            assert!(out.stdout.is_empty());
        }
    }
    for digest in ["sha1", "sha512-224", "sha512-256"] {
        assert_eq!(
            run(
                Path::new("/missing"),
                "derive-kbkdf",
                Some(digest),
                "counter",
                &[]
            )
            .status
            .code(),
            Some(2)
        );
    }
}
#[test]
fn new_profiles_withhold_success_on_native_and_cleanup_failures() {
    for (digest, mechanism, typed, length) in PROFILES {
        for (offset, mode) in [(0, "counter"), (20, "feedback"), (40, "double-pipeline")] {
            for fault in [5, 10, 11] {
                let fixture = KbkdfCmacModule::hmac(3, 2, offset + fault, mechanism, typed, length);
                let out = run(&fixture.path(), "derive-kbkdf", Some(digest), mode, &[]);
                assert_eq!(out.status.code(), Some(5));
                assert!(out.stdout.is_empty());
            }
        }
    }
}
