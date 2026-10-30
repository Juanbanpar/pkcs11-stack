// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 8032 signatures, raw provisioning and file/stdin through the CLI.
#[path = "../../pkcs11-runtime/tests/fixtures/eddsa_named_vectors.rs"]
#[allow(dead_code)]
mod vectors;
use pkcs11_client::EdDsaNamedScheme;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
fn uri(id: u8, kind: &str) -> String {
    format!("pkcs11:token=kdf-test;id=%D9%ED%01%{id:02X};type={kind}")
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store with Edwards support"]
fn named_eddsa_cli_matches_rfc8032_and_round_trips_generated_keys() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let pin = root.join("eddsa-cli.pin");
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
        let out = run(args, input);
        assert!(out.status.success(), "{args:?}: {out:?}");
        assert!(out.stderr.is_empty());
        out.stdout
    };
    let options: serde_json::Value = serde_json::from_slice(&ok(
        &["generation-options", "--token", "pkcs11:token=kdf-test"],
        None,
    ))
    .unwrap();
    assert_eq!(
        options["result"]["eddsa_named"].as_array().unwrap().len(),
        2
    );
    let message = root.join("eddsa-message");
    let context = root.join("eddsa-context");
    let signature = root.join("eddsa-signature");
    for (index, vector) in vectors::VECTORS.iter().enumerate() {
        let scheme = match vector.scheme {
            pkcs11_client::EdDsaNamedScheme::Ed25519 => "ed25519",
            pkcs11_client::EdDsaNamedScheme::Ed25519ctx => "ed25519ctx",
            pkcs11_client::EdDsaNamedScheme::Ed25519ph => "ed25519ph",
            pkcs11_client::EdDsaNamedScheme::Ed448 => "ed448",
            pkcs11_client::EdDsaNamedScheme::Ed448ph => "ed448ph",
        };
        let raw_message = vectors::hex(vector.message);
        std::fs::write(&message, &raw_message).unwrap();
        std::fs::write(&context, vectors::hex(vector.context)).unwrap();
        let signed = ok(
            &[
                "sign-eddsa-named",
                "--object",
                &uri(index as u8, "private"),
                "--scheme",
                scheme,
                "--context-file",
                context.to_str().unwrap(),
                "--input",
                "-",
                "--output",
                "-",
            ],
            Some(&raw_message),
        );
        assert_eq!(signed, vectors::hex(vector.signature));
        std::fs::write(&signature, &signed).unwrap();
        ok(
            &[
                "verify-eddsa-named",
                "--object",
                &uri(index as u8, "public"),
                "--scheme",
                scheme,
                "--context-file",
                context.to_str().unwrap(),
                "--input",
                message.to_str().unwrap(),
                "--signature",
                "-",
            ],
            Some(&signed),
        );
        let bad = run(
            &[
                "verify-eddsa-named",
                "--object",
                &uri(index as u8, "public"),
                "--scheme",
                scheme,
                "--context-file",
                context.to_str().unwrap(),
                "--input",
                "-",
                "--signature",
                signature.to_str().unwrap(),
            ],
            Some(b"wrong message"),
        );
        assert_eq!(bad.status.code(), Some(4));
        assert!(bad.stdout.is_empty());
    }
    for (id, kind, scheme) in [
        (0xc0, "edwards25519", "ed25519ph"),
        (0xc1, "edwards448", "ed448ph"),
    ] {
        let id_hex = format!("d9ed01{id:02x}");
        ok(
            &[
                "generate",
                "--token",
                "pkcs11:token=kdf-test",
                "--kind",
                kind,
                "--id",
                &id_hex,
                "--label",
                "CLI Edwards",
                "--always-authenticate",
                "--confirm",
            ],
            None,
        );
        let generated = ok(
            &[
                "export",
                "--object",
                &uri(id, "public"),
                "--key-family",
                kind,
                "--output",
                "-",
            ],
            None,
        );
        let imported_hex = format!("d9ed01{:02x}", id + 2);
        ok(
            &[
                "import",
                "--token",
                "pkcs11:token=kdf-test",
                "--kind",
                kind,
                "--id",
                &imported_hex,
                "--label",
                "CLI imported Edwards",
                "--input",
                "-",
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
                kind,
                "--id",
                &imported_hex,
                "--label",
                "duplicate",
                "--input",
                "-",
                "--confirm",
            ],
            Some(&generated),
        );
        assert_eq!(duplicate.status.code(), Some(2));
        assert!(duplicate.stdout.is_empty());
        assert_eq!(
            ok(
                &[
                    "export",
                    "--object",
                    &uri(id + 2, "public"),
                    "--key-family",
                    kind,
                    "--output",
                    "-"
                ],
                None
            ),
            generated
        );
        std::fs::write(&context, [0xa5; 255]).unwrap();
        std::fs::write(&message, b"generated EdDSA").unwrap();
        let signed = ok(
            &[
                "sign-eddsa-named",
                "--object",
                &uri(id, "private"),
                "--scheme",
                scheme,
                "--context-file",
                context.to_str().unwrap(),
                "--context-pin-file",
                pin.to_str().unwrap(),
                "--input",
                message.to_str().unwrap(),
                "--output",
                "-",
            ],
            None,
        );
        std::fs::write(&signature, signed).unwrap();
        ok(
            &[
                "verify-eddsa-named",
                "--object",
                &uri(id + 2, "public"),
                "--scheme",
                scheme,
                "--context-file",
                context.to_str().unwrap(),
                "--input",
                message.to_str().unwrap(),
                "--signature",
                signature.to_str().unwrap(),
            ],
            None,
        );
    }
}
