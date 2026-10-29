// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI agreement/HKDF matches RFC 7748 and OpenSSL through token encryption.
use std::{path::PathBuf, process::Command};
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn x25519_cli_export_agreement_and_hkdf_keep_secret_values_on_token() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let pin = root.join("x25519-cli.pin");
    std::fs::write(&pin, b"12345678\n").unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .arg("--module")
            .arg(&module)
            .args(["--format", "json"])
            .args(args)
            .arg("--pin-file")
            .arg(&pin)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty());
        output.stdout
    };
    assert_eq!(
        run(&[
            "export",
            "--object",
            "pkcs11:token=kdf-test;id=%D9%58%02;type=public",
            "--key-family",
            "x25519",
            "--output",
            "-"
        ]),
        std::fs::read(root.join("x25519-peer.der")).unwrap()
    );
    let result = run(&[
        "derive-x25519",
        "--object",
        "pkcs11:token=kdf-test;id=%D9%58%01;type=private",
        "--input",
        root.join("x25519-peer.der").to_str().unwrap(),
        "--id",
        "d95840",
        "--label",
        "CLI X25519",
        "--confirm",
    ]);
    let result: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(result["result"]["length"], 32);
    run(&[
        "derive-hkdf",
        "--object",
        "pkcs11:token=kdf-test;id=%D9%58%40;type=secret-key",
        "--digest",
        "sha256",
        "--kind",
        "aes256",
        "--salt-file",
        root.join("x25519-salt").to_str().unwrap(),
        "--info-file",
        root.join("x25519-info").to_str().unwrap(),
        "--id",
        "d95841",
        "--label",
        "CLI X25519 HKDF",
        "--confirm",
    ]);
    let ciphertext = run(&[
        "encrypt-aes-gcm",
        "--object",
        "pkcs11:token=kdf-test;id=%D9%58%41;type=secret-key",
        "--nonce",
        "010101010101010101010101",
        "--aad-file",
        root.join("x25519-aad").to_str().unwrap(),
        "--input",
        root.join("x25519-plaintext").to_str().unwrap(),
        "--output",
        "-",
    ]);
    assert_eq!(
        ciphertext,
        std::fs::read(root.join("x25519-expected-gcm")).unwrap()
    );
}
