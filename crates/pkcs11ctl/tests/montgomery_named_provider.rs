// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI curveName provisioning, raw file/stdin agreement and SP800-108 chaining.
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
fn uri(group: u8, id: u8, kind: &str) -> String {
    format!("pkcs11:token=kdf-test;id=%D9%77%{group:02X}%{id:02X};type={kind}")
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn cli_named_profiles_round_trip_raw_keys_and_match_reference_ciphertexts() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let pin = root.join("named-cli.pin");
    std::fs::write(&pin, b"12345678\n").unwrap();
    let run = |args: &[&str], input: Option<&[u8]>| -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command
            .arg("--module")
            .arg(&module)
            .args(["--format", "json"])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if args[0] != "generation-options" {
            command.arg("--pin-file").arg(&pin);
        }
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().unwrap();
        if let Some(bytes) = input {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        }
        child.wait_with_output().unwrap()
    };
    let ok = |args: &[&str], input: Option<&[u8]>| {
        let output = run(args, input);
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert!(output.stderr.is_empty());
        output.stdout
    };
    let options: serde_json::Value = serde_json::from_slice(&ok(
        &["generation-options", "--token", "pkcs11:token=kdf-test"],
        None,
    ))
    .unwrap();
    assert_eq!(
        options["result"]["montgomery_named"],
        serde_json::json!(["curve25519", "curve448"])
    );
    let label = root.join("named-kdf-label");
    std::fs::write(&label, b"curveName test").unwrap();
    let context = root.join("named-kdf-context");
    std::fs::write(&context, b"RFC7748 v1").unwrap();
    let message = root.join("named-message");
    std::fs::write(&message, b"public agreement proof").unwrap();
    let aad = root.join("named-aad");
    std::fs::write(&aad, b"curveName test").unwrap();
    for (group, curve, length) in [(1, "curve25519", 32), (2, "curve448", 56)] {
        let bob = ok(
            &[
                "export",
                "--object",
                &uri(group, 2, "public"),
                "--key-family",
                curve,
                "--output",
                "-",
            ],
            None,
        );
        assert_eq!(bob.len(), length);
        let bob_path = root.join(format!("named-bob-{group}.raw"));
        std::fs::write(&bob_path, &bob).unwrap();
        let pair_id = format!("d977{group:02x}40");
        ok(
            &[
                "generate",
                "--token",
                "pkcs11:token=kdf-test",
                "--kind",
                curve,
                "--id",
                &pair_id,
                "--label",
                "CLI curveName",
                "--confirm",
            ],
            None,
        );
        let generated_path = root.join(format!("named-generated-{group}.raw"));
        ok(
            &[
                "export",
                "--object",
                &uri(group, 0x40, "public"),
                "--key-family",
                curve,
                "--output",
                generated_path.to_str().unwrap(),
            ],
            None,
        );
        let generated = std::fs::read(&generated_path).unwrap();
        assert_eq!(generated.len(), length);
        let imported_id = format!("d977{group:02x}41");
        ok(
            &[
                "import",
                "--token",
                "pkcs11:token=kdf-test",
                "--kind",
                curve,
                "--input",
                "-",
                "--id",
                &imported_id,
                "--label",
                "CLI curveName peer",
                "--confirm",
            ],
            Some(&generated),
        );
        let duplicate = run(
            &[
                "import",
                "--token",
                "pkcs11:token=kdf-test",
                "--kind",
                curve,
                "--input",
                generated_path.to_str().unwrap(),
                "--id",
                &imported_id,
                "--label",
                "duplicate",
                "--confirm",
            ],
            None,
        );
        assert_eq!(duplicate.status.code(), Some(2));
        assert!(duplicate.stdout.is_empty());
        assert_eq!(
            ok(
                &[
                    "export",
                    "--object",
                    &uri(group, 0x41, "public"),
                    "--key-family",
                    curve,
                    "--output",
                    "-"
                ],
                None
            ),
            generated
        );
        let mut ciphertexts = Vec::new();
        for (base, peer, id) in [
            (1, bob.as_slice(), 0x42),
            (0x40, bob.as_slice(), 0x44),
            (2, generated.as_slice(), 0x46),
        ] {
            let secret_id = format!("d977{group:02x}{id:02x}");
            let input = if id == 0x42 {
                bob_path.to_str().unwrap()
            } else {
                "-"
            };
            let args = [
                "derive-montgomery",
                "--object",
                &uri(group, base, "private"),
                "--curve",
                curve,
                "--input",
                input,
                "--id",
                &secret_id,
                "--label",
                "CLI named raw",
                "--confirm",
            ];
            let stdout = ok(&args, if input == "-" { Some(peer) } else { None });
            let result: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
            assert_eq!(result["result"]["length"], length);
            assert_eq!(result["result"]["extractable"], false);
            assert_eq!(result["result"]["curve"], curve);
            let duplicate = run(&args, if input == "-" { Some(peer) } else { None });
            assert_eq!(duplicate.status.code(), Some(2));
            assert!(duplicate.stdout.is_empty());
            let aes_id = format!("d977{group:02x}{:02x}", id + 1);
            ok(
                &[
                    "derive-kbkdf",
                    "--object",
                    &uri(group, id, "secret-key"),
                    "--digest",
                    "sha512",
                    "--kind",
                    "aes256",
                    "--kdf-label-file",
                    label.to_str().unwrap(),
                    "--kdf-context-file",
                    context.to_str().unwrap(),
                    "--id",
                    &aes_id,
                    "--label",
                    "CLI named AES",
                    "--confirm",
                ],
                None,
            );
            ciphertexts.push(ok(
                &[
                    "encrypt-aes-gcm",
                    "--object",
                    &uri(group, id + 1, "secret-key"),
                    "--nonce",
                    "070707070707070707070707",
                    "--aad-file",
                    aad.to_str().unwrap(),
                    "--input",
                    message.to_str().unwrap(),
                    "--output",
                    "-",
                ],
                None,
            ));
        }
        let oracle = ok(
            &[
                "encrypt-aes-gcm",
                "--object",
                &uri(group, 5, "secret-key"),
                "--nonce",
                "070707070707070707070707",
                "--aad-file",
                aad.to_str().unwrap(),
                "--input",
                message.to_str().unwrap(),
                "--output",
                "-",
            ],
            None,
        );
        assert_eq!(ciphertexts[0], oracle);
        assert_eq!(ciphertexts[1], ciphertexts[2]);
        let wrong = run(
            &[
                "export",
                "--object",
                &uri(group, 0x40, "public"),
                "--key-family",
                if group == 1 { "x25519" } else { "x448" },
                "--output",
                "-",
            ],
            None,
        );
        assert!(!wrong.status.success());
        assert!(wrong.stdout.is_empty());
    }
}
