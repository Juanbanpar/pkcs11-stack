// SPDX-License-Identifier: MIT OR Apache-2.0
//! HashML-DSA CLI preflight and checked output release.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/hash_ml_dsa_module.rs"]
mod fixture;
use fixture::HashMlDsaModule;
use std::{
    path::PathBuf,
    process::{Command, Output},
};
struct Fixture {
    module: HashMlDsaModule,
    root: PathBuf,
    prehash: bool,
    verify: bool,
}
impl Fixture {
    fn new(version: (u8, u8), fault: u8, prehash: bool, verify: bool) -> Self {
        let module = HashMlDsaModule::new(version.0, version.1, fault, 0, 1, 0, 1, prehash, verify);
        let root = module.path().parent().unwrap().join("cli");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("input"),
            if prehash {
                vec![0xA5; 64]
            } else {
                b"abc".to_vec()
            },
        )
        .unwrap();
        std::fs::write(root.join("signature"), vec![0xAB; 2420]).unwrap();
        std::fs::write(root.join("pin"), b"1234").unwrap();
        Self {
            module,
            root,
            prehash,
            verify,
        }
    }
    fn run(&self, extras: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command
            .arg("--module")
            .arg(self.module.path())
            .args([
                "--format",
                "json",
                if self.verify {
                    "verify-hash-ml-dsa"
                } else {
                    "sign-hash-ml-dsa"
                },
                "--object",
                if self.verify {
                    "pkcs11:token=cmac;id=%01;type=public"
                } else {
                    "pkcs11:token=cmac;id=%01;type=private"
                },
                "--parameter-set",
                "ml-dsa-44",
                "--input-kind",
                if self.prehash { "digest" } else { "message" },
            ])
            .arg("--input")
            .arg(self.root.join("input"));
        if self.verify {
            command.arg("--signature").arg(self.root.join("signature"));
        } else {
            command
                .args(["--output", "-", "--context-pin-file"])
                .arg(self.root.join("pin"));
        }
        command.args(extras).output().unwrap()
    }
}
#[test]
fn native_single_part_profiles_keep_legacy_and_current_table_support() {
    for version in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        for prehash in [false, true] {
            for verify in [false, true] {
                let f = Fixture::new(version, 0, prehash, verify);
                let output = f.run(&[]);
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(output.stderr.is_empty());
                if verify {
                    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                    assert_eq!(value["result"]["verified"], true);
                } else {
                    assert_eq!(output.stdout, vec![0xAB; 2420]);
                }
            }
        }
    }
}
#[test]
fn native_and_cleanup_failures_release_no_output() {
    for prehash in [false, true] {
        for verify in [false, true] {
            let faults = if verify {
                vec![11, 18, 19, 20, 21, 22, 23, 24]
            } else {
                vec![11, 12, 13, 14, 15, 16, 17, 22, 23, 24]
            };
            for fault in faults {
                let f = Fixture::new((3, 2), fault, prehash, verify);
                let output = f.run(&[]);
                assert!(!output.status.success(), "fault {fault}");
                assert!(output.stdout.is_empty());
                assert!(!String::from_utf8_lossy(&output.stderr).contains("1234"));
            }
        }
    }
}
#[test]
fn malformed_digest_context_and_signature_fail_before_loading_a_module() {
    for length in [0, 63, 65] {
        let f = Fixture::new((3, 2), 0, true, false);
        std::fs::write(f.root.join("input"), vec![0; length]).unwrap();
        let output = f.run(&[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    for verify in [false, true] {
        let f = Fixture::new((3, 2), 0, false, verify);
        let context = f.root.join("context");
        std::fs::write(&context, [0; 256]).unwrap();
        let output = f.run(&["--context-file", context.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        if verify {
            std::fs::write(f.root.join("signature"), [0; 2419]).unwrap();
            assert_eq!(f.run(&[]).status.code(), Some(2));
        }
    }
}
