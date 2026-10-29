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
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command
            .arg("--module")
            .arg(&module)
            .args(["--format", "json"])
            .args(args);
        if args[0] != "generation-options" {
            command.arg("--pin-file").arg(&pin);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
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
    let options: serde_json::Value = serde_json::from_slice(&run(&[
        "generation-options",
        "--token",
        "pkcs11:token=kdf-test",
    ]))
    .unwrap();
    assert_eq!(options["result"]["x25519"], true);
    let generated: serde_json::Value = serde_json::from_slice(&run(&[
        "generate",
        "--token",
        "pkcs11:token=kdf-test",
        "--kind",
        "x25519",
        "--id",
        "d95870",
        "--label",
        "CLI generated X25519",
        "--confirm",
    ]))
    .unwrap();
    assert_eq!(generated["result"]["key"]["purpose"], "derivation");
    assert_eq!(generated["result"]["extractable"], false);
    let public = run(&[
        "export",
        "--object",
        "pkcs11:token=kdf-test;id=%D9%58%70;type=public",
        "--key-family",
        "x25519",
        "--output",
        "-",
    ]);
    pkcs11_client::X25519Peer::from_spki_der(&public).unwrap();
    let input = root.join("cli-generated-x25519.der");
    std::fs::write(&input, &public).unwrap();
    let import = [
        "import",
        "--token",
        "pkcs11:token=kdf-test",
        "--kind",
        "x25519",
        "--id",
        "d95871",
        "--label",
        "CLI imported X25519",
        "--input",
        input.to_str().unwrap(),
        "--confirm",
    ];
    let imported: serde_json::Value = serde_json::from_slice(&run(&import)).unwrap();
    assert_eq!(imported["result"]["key"]["type"], "x25519");
    assert_eq!(
        run(&[
            "export",
            "--object",
            "pkcs11:token=kdf-test;id=%D9%58%71;type=public",
            "--key-family",
            "x25519",
            "--output",
            "-",
        ]),
        public
    );
    let duplicate = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .arg("--module")
        .arg(&module)
        .args(["--format", "json"])
        .args(import)
        .arg("--pin-file")
        .arg(&pin)
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(duplicate.stdout.is_empty());
    run(&[
        "derive-x25519",
        "--object",
        "pkcs11:token=kdf-test;id=%D9%58%70;type=private",
        "--input",
        root.join("x25519-peer.der").to_str().unwrap(),
        "--id",
        "d95872",
        "--label",
        "CLI generated agreement",
        "--confirm",
    ]);
}
