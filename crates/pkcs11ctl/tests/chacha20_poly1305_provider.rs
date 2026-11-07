// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI file/stdin ChaCha20-Poly1305 workflows agree with RFC 8439 known answers and preserve output on failure.
#[path = "../../pkcs11-runtime/tests/fixtures/chacha20_poly1305_vectors.rs"]
mod vectors;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn ok(result: Output) -> Vec<u8> {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    result.stdout
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh after runtime AES-ChaCha20-Poly1305 provisioning"]
fn chacha_cli_rfc8439_vectors_stdin_empty_messages_and_authentication_failures() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let pin = root.join("chacha-cli.pin");
    std::fs::write(&pin, b"12345678").unwrap();
    let run = |args: &[&str], stdin: Option<&[u8]>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command
            .arg("--module")
            .arg(&module)
            .args(["--format", "json"])
            .args(args)
            .arg("--pin-file")
            .arg(&pin)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        if let Some(bytes) = stdin {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        }
        child.wait_with_output().unwrap()
    };
    for (index, v) in vectors::VECTORS.iter().enumerate() {
        let key = format!("pkcs11:token=kdf-test;object=chacha-kat-{index};type=secret-key");
        let input = root.join(format!("chacha-cli-{index}.message"));
        let aad = root.join(format!("chacha-cli-{index}.aad"));
        let ct = root.join(format!("chacha-cli-{index}.ciphertext"));
        let pt = root.join(format!("chacha-cli-{index}.plaintext"));
        std::fs::write(&input, hex(v.plaintext)).unwrap();
        std::fs::write(&aad, hex(v.aad)).unwrap();
        let caps: serde_json::Value = serde_json::from_slice(&ok(run(
            &[
                "chacha20-poly1305-capabilities",
                "--object",
                &key,
                "--operation",
                "encrypt",
            ],
            None,
        )))
        .unwrap();
        assert_eq!(caps["result"]["key_bits"], v.key.len() * 4);
        assert_eq!(caps["result"]["tag_length"], 16);
        assert_eq!(caps["result"]["maximum_plaintext"], 16777216);
        let mut args = vec![
            "encrypt-chacha20-poly1305",
            "--object",
            &key,
            "--nonce",
            v.nonce,
            "--aad-file",
            aad.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--output",
            ct.to_str().unwrap(),
        ];
        ok(run(&args, None));
        assert_eq!(std::fs::read(&ct).unwrap(), hex(v.ciphertext));
        args[8] = "-";
        args[10] = "-";
        assert_eq!(ok(run(&args, Some(&hex(v.plaintext)))), hex(v.ciphertext));
        let mut decryption = vec![
            "decrypt-chacha20-poly1305",
            "--object",
            &key,
            "--nonce",
            v.nonce,
            "--aad-file",
            aad.to_str().unwrap(),
            "--input",
            ct.to_str().unwrap(),
            "--output",
            pt.to_str().unwrap(),
        ];
        ok(run(&decryption, None));
        assert_eq!(std::fs::read(&pt).unwrap(), hex(v.plaintext));
        decryption[8] = "-";
        decryption[10] = "-";
        assert_eq!(
            ok(run(&decryption, Some(&hex(v.ciphertext)))),
            hex(v.plaintext)
        );
        let mut tampered = hex(v.ciphertext);
        *tampered.last_mut().unwrap() ^= 1;
        std::fs::write(&ct, tampered).unwrap();
        decryption[8] = ct.to_str().unwrap();
        let result = run(&decryption, None);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        decryption[10] = pt.to_str().unwrap();
        assert!(!run(&decryption, None).status.success());
        assert_eq!(std::fs::read(&pt).unwrap(), hex(v.plaintext));
    }
    ok(run(
        &[
            "generate",
            "--token",
            "pkcs11:token=kdf-test",
            "--kind",
            "chacha20-poly1305",
            "--id",
            "6368616368612d636c69",
            "--label",
            "chacha-cli-generated",
            "--confirm",
        ],
        None,
    ));
    let key = "pkcs11:token=kdf-test;object=chacha-cli-generated;type=secret-key";
    let ct = ok(run(
        &[
            "encrypt-chacha20-poly1305",
            "--object",
            key,
            "--nonce",
            "193847562738475610293847",
            "--input",
            "-",
            "--output",
            "-",
        ],
        Some(b""),
    ));
    assert_eq!(ct.len(), 16);
    assert!(
        ok(run(
            &[
                "decrypt-chacha20-poly1305",
                "--object",
                key,
                "--nonce",
                "193847562738475610293847",
                "--input",
                "-",
                "--output",
                "-"
            ],
            Some(&ct)
        ))
        .is_empty()
    );
}
