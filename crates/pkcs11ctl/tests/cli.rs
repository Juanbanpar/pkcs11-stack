// SPDX-License-Identifier: MIT OR Apache-2.0
//! Executable contracts that require no PKCS#11 library.
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "pkcs11ctl-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn help_and_version_need_no_module() {
    for name in [
        "info",
        "slots",
        "tokens",
        "objects",
        "mechanisms",
        "inspect",
        "export",
        "certificate",
        "capabilities",
        "plan",
        "bind",
        "sign",
        "diagnose",
        "init-token",
        "init-pin",
        "set-pin",
        "generate",
        "import",
        "set-label",
        "delete",
    ] {
        let out = run(&[name, "--help"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stderr.is_empty());
    }
    assert!(run(&["--version"]).status.success());
}
#[test]
fn rejects_arguments_without_echoing_secrets() {
    let marker = "do-not-echo-this-secret";
    for args in [
        vec![
            "--format", "json", "inspect", "--object", marker, "--bad", marker,
        ],
        vec![
            "--format",
            "json",
            "--module",
            "/missing",
            "inspect",
            "--object",
            "pkcs11:token=x;object=y?pin-value=do-not-echo-this-secret",
        ],
        vec![
            "--format",
            "json",
            "--module",
            "/missing",
            "delete",
            "--object",
            "pkcs11:token=x;object=y",
        ],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        let text = String::from_utf8(out.stderr).unwrap();
        assert!(!text.contains(marker));
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["error"]["kind"], "input");
    }
}
#[test]
fn validates_parameters_before_loading_module() {
    let dir = Scratch::new();
    let file = dir.0.join("input");
    std::fs::write(&file, b"message").unwrap();
    let args = [
        "--module",
        "/missing",
        "plan",
        "--key",
        "pkcs11:token=x;object=k;type=private",
        "--algorithm",
        "rsa-pss",
        "--digest",
        "sha256",
        "--input",
        file.to_str().unwrap(),
    ];
    let out = run(&args);
    assert_eq!(out.status.code(), Some(2));
    let out = run(&[
        "--module",
        "/missing",
        "diagnose",
        "--token",
        "pkcs11:token=x;object=ignored",
        "--pool-size",
        "0",
    ]);
    assert_eq!(out.status.code(), Some(2));
    let out = run(&[
        "--module",
        "/missing",
        "generate",
        "--token",
        "pkcs11:token=x",
        "--kind",
        "p256",
        "--bits",
        "2048",
        "--id",
        "01",
        "--label",
        "key",
        "--confirm",
    ]);
    assert_eq!(out.status.code(), Some(2));
}
#[test]
fn existing_output_is_preserved_and_failed_output_removed() {
    let dir = Scratch::new();
    let input = dir.0.join("input");
    let output = dir.0.join("output");
    std::fs::write(&input, b"message").unwrap();
    std::fs::write(&output, b"preserve").unwrap();
    let args = [
        "--module",
        "/missing",
        "sign",
        "--key",
        "pkcs11:token=x;object=k;type=private",
        "--algorithm",
        "rsa-pkcs1",
        "--digest",
        "sha256",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ];
    assert_eq!(run(&args).status.code(), Some(6));
    assert_eq!(std::fs::read(&output).unwrap(), b"preserve");
    std::fs::remove_file(&output).unwrap();
    assert_eq!(run(&args).status.code(), Some(5));
    assert!(!output.exists());
}

#[test]
fn malformed_prehash_is_rejected_before_loading_or_creating_output() {
    let dir = Scratch::new();
    let input = dir.0.join("digest");
    let output = dir.0.join("signature");
    std::fs::write(&input, [0; 31]).unwrap();
    let result = run(&[
        "--module",
        "/missing",
        "--format",
        "json",
        "sign",
        "--key",
        "pkcs11:token=test;object=key;type=private",
        "--algorithm",
        "rsa-pkcs1",
        "--digest",
        "sha256",
        "--input-kind",
        "digest",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(
        result.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.exists());
    assert!(result.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "input");
}

#[test]
fn typed_selectors_are_rejected_before_loading_module() {
    for args in [
        vec![
            "capabilities",
            "--key",
            "pkcs11:token=test;object=key;type=cert",
        ],
        vec!["capabilities", "--key", "pkcs11:token=test;object=key"],
        vec![
            "certificate",
            "--object",
            "pkcs11:token=test;object=cert;type=private",
        ],
        vec![
            "bind",
            "--key",
            "pkcs11:token=test;object=key;type=private",
            "--certificate",
            "pkcs11:token=test;object=cert;type=public",
        ],
    ] {
        let mut all = vec!["--module", "/missing", "--format", "json"];
        all.extend(args);
        let result = run(&all);
        assert_eq!(
            result.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
        assert_eq!(error["error"]["kind"], "input");
    }
}
