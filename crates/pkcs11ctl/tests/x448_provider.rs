// SPDX-License-Identifier: MIT OR Apache-2.0
//! X448 CLI public export, file/stdin agreement, KDF selection and HKDF chaining.
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn x448_cli_matches_independent_reference_ciphertexts() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let pin = root.join("x448-cli.pin");
    std::fs::write(&pin, b"12345678\n").unwrap();
    let run = |args: &[&str], input: Option<&[u8]>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command
            .arg("--module")
            .arg(&module)
            .args(["--format", "json"])
            .args(args)
            .arg("--pin-file")
            .arg(&pin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().unwrap();
        if let Some(bytes) = input {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert!(output.stderr.is_empty());
        output.stdout
    };
    let peer = std::fs::read(root.join("x448-peer.der")).unwrap();
    assert_eq!(
        run(
            &[
                "export",
                "--object",
                "pkcs11:token=kdf-test;id=%D9%48%02;type=public",
                "--key-family",
                "x448",
                "--output",
                "-"
            ],
            None
        ),
        peer
    );
    for (id, kdf, kind, length, name) in [
        ("d94880", "null", "raw-secret", 56, None),
        ("d94881", "x963-sha512", "aes256", 32, Some("x963")),
        ("d94882", "nist-sha512", "aes256", 32, Some("nist")),
        ("d94883", "nist-sha512", "secret", 64, None),
    ] {
        let mut args = vec![
            "derive-x448",
            "--object",
            "pkcs11:token=kdf-test;id=%D9%48%01;type=private",
            "--kdf",
            kdf,
            "--kind",
            kind,
            "--id",
            id,
            "--label",
            "CLI X448",
            "--confirm",
            "--input",
        ];
        let peer_path = root.join("x448-peer.der");
        let info_path = root.join("x448-info");
        args.push(if kdf == "null" {
            "-"
        } else {
            peer_path.to_str().unwrap()
        });
        if kdf != "null" {
            args.extend(["--shared-info-file", info_path.to_str().unwrap()]);
        }
        let output = run(&args, if kdf == "null" { Some(&peer) } else { None });
        let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["result"]["length"], length);
        assert_eq!(result["result"]["extractable"], false);
        if let Some(name) = name {
            let uri = format!(
                "pkcs11:token=kdf-test;id=%D9%48%{};type=secret-key",
                &id[4..]
            );
            let message = root.join("x448-message");
            std::fs::write(&message, b"public X448 challenge").unwrap();
            let aad = root.join("x448-aad");
            std::fs::write(&aad, b"X448 test").unwrap();
            let cipher = run(
                &[
                    "encrypt-aes-gcm",
                    "--object",
                    &uri,
                    "--nonce",
                    "040404040404040404040404",
                    "--aad-file",
                    aad.to_str().unwrap(),
                    "--input",
                    message.to_str().unwrap(),
                    "--output",
                    "-",
                ],
                None,
            );
            assert_eq!(
                cipher,
                std::fs::read(root.join(format!("x448-{name}-cipher-32"))).unwrap()
            );
        }
    }
    let salt = root.join("x448-salt");
    std::fs::write(&salt, b"X448 salt").unwrap();
    let info = root.join("x448-hkdf-info");
    std::fs::write(&info, b"X448 HKDF v1").unwrap();
    run(
        &[
            "derive-hkdf",
            "--object",
            "pkcs11:token=kdf-test;id=%D9%48%83;type=secret-key",
            "--digest",
            "sha512",
            "--kind",
            "aes256",
            "--salt-file",
            salt.to_str().unwrap(),
            "--info-file",
            info.to_str().unwrap(),
            "--id",
            "d94884",
            "--label",
            "CLI X448 HKDF",
            "--confirm",
        ],
        None,
    );
    let cipher = run(
        &[
            "encrypt-aes-gcm",
            "--object",
            "pkcs11:token=kdf-test;id=%D9%48%84;type=secret-key",
            "--nonce",
            "040404040404040404040404",
            "--aad-file",
            root.join("x448-aad").to_str().unwrap(),
            "--input",
            root.join("x448-message").to_str().unwrap(),
            "--output",
            "-",
        ],
        None,
    );
    assert_eq!(
        cipher,
        std::fs::read(root.join("x448-hkdf-cipher")).unwrap()
    );
}
