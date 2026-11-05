// SPDX-License-Identifier: MIT OR Apache-2.0
//! Binary password preflight, exact native PRFs and checked output release.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/pbkdf2_module.rs"]
mod fixture;
use fixture::Pbkdf2Module;
use std::{
    path::Path,
    process::{Command, Output},
};
fn run(module: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .arg("--module")
        .arg(module)
        .args(["--format", "json"])
        .args(args)
        .output()
        .unwrap()
}
fn args<'a>(password: &'a str, salt: &'a str, digest: &'a str) -> Vec<&'a str> {
    vec![
        "generate-pbkdf2",
        "--token",
        "pkcs11:token=cmac",
        "--password-file",
        password,
        "--salt-file",
        salt,
        "--digest",
        digest,
        "--iterations",
        "2",
        "--kind",
        "aes256",
        "--id",
        "03",
        "--label",
        "output",
        "--confirm",
    ]
}
#[test]
fn binary_password_prfs_and_native_cleanup_failures() {
    for (digest, prf) in [
        ("sha224", "CKP_PKCS5_PBKD2_HMAC_SHA224"),
        ("sha256", "CKP_PKCS5_PBKD2_HMAC_SHA256"),
        ("sha384", "CKP_PKCS5_PBKD2_HMAC_SHA384"),
        ("sha512", "CKP_PKCS5_PBKD2_HMAC_SHA512"),
        ("sha512-224", "CKP_PKCS5_PBKD2_HMAC_SHA512_224"),
        ("sha512-256", "CKP_PKCS5_PBKD2_HMAC_SHA512_256"),
    ] {
        for fault in [0, 1, 2, 3, 4, 5, 6, 7, 8] {
            let f = Pbkdf2Module::new(3, 2, fault, prf);
            let root = f.path().parent().unwrap().to_path_buf();
            let password = root.join("password");
            let salt = root.join("salt");
            std::fs::write(&password, [b'p', 0, 0xff, b'\n']).unwrap();
            std::fs::write(&salt, b"salt").unwrap();
            let out = run(
                &f.path(),
                &args(password.to_str().unwrap(), salt.to_str().unwrap(), digest),
            );
            assert_eq!(
                out.status.success(),
                fault == 0,
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            if fault == 0 {
                let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                assert_eq!(value["result"]["generated"], true);
                assert_eq!(value["result"]["digest"], digest);
                assert!(!String::from_utf8_lossy(&out.stdout).contains("password"));
            } else {
                assert!(out.stdout.is_empty());
            }
        }
    }
}
#[test]
fn invalid_inputs_precede_module_loading() {
    let f = Pbkdf2Module::new(2, 40, 0, "CKP_PKCS5_PBKD2_HMAC_SHA256");
    let root = f.path().parent().unwrap().to_path_buf();
    let password = root.join("password");
    let salt = root.join("salt");
    std::fs::write(&password, b"p").unwrap();
    std::fs::write(&salt, b"salt").unwrap();
    let base = args(password.to_str().unwrap(), salt.to_str().unwrap(), "sha256");
    for (option, value) in [
        ("--password-file", "-"),
        ("--salt-file", "-"),
        ("--iterations", "0"),
        ("--iterations", "4294967296"),
        ("--iterations", "10000001"),
        ("--digest", "sha1"),
        ("--digest", "sha3-256"),
        ("--id", ""),
        ("--label", ""),
        ("--token", "pkcs11:token=cmac;type=secret-key"),
    ] {
        let mut args = base.clone();
        let pos = args.iter().position(|v| *v == option).unwrap();
        args[pos + 1] = value;
        let out = run(Path::new("/missing"), &args);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
    for length in [0, 4096, 4097] {
        std::fs::write(&password, vec![0; length]).unwrap();
        assert_eq!(
            run(Path::new("/missing"), &base).status.code(),
            Some(if length <= 4096 { 5 } else { 2 })
        );
    }
    std::fs::write(&password, b"p").unwrap();
    for length in [0, 4096, 4097] {
        std::fs::write(&salt, vec![0; length]).unwrap();
        assert_eq!(
            run(Path::new("/missing"), &base).status.code(),
            Some(if length == 4096 { 5 } else { 2 })
        );
    }
    std::fs::write(&salt, b"salt").unwrap();
    for extra in [
        vec!["--kind", "aes256", "--length", "32"],
        vec!["--kind", "derivation-secret", "--length", "0"],
        vec!["--kind", "derivation-secret", "--length", "4097"],
        vec![
            "--kind",
            "derivation-secret",
            "--length",
            "4096",
            "--iterations",
            "100000",
        ],
        vec!["--role", "so"],
    ] {
        let mut a = base.clone();
        for pair in extra.chunks(2) {
            if let Some(pos) = a.iter().position(|v| *v == pair[0]) {
                a[pos + 1] = pair[1];
            } else {
                a.extend_from_slice(pair);
            }
        }
        assert_eq!(run(Path::new("/missing"), &a).status.code(), Some(2));
    }
}
