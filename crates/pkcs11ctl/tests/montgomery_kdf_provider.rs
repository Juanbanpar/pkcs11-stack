// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI KDF selection, raw/SPKI input, generic chaining and independent AES proofs.
#[path = "../../pkcs11-runtime/tests/fixtures/montgomery_kdf_cases.rs"]
#[allow(dead_code)]
mod cases;
use pkcs11_client::{AesKeySize, DigestAlgorithm, EcdhKdf, MontgomeryOutput};
use std::{
    io::Write,
    process::{Command, Stdio},
};
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn cli_native_kdfs_match_independent_reference_ciphertexts() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let pin = root.join("montgomery-kdf.pin");
    std::fs::write(&pin, b"12345678\n").unwrap();
    let run = |args: &[&str], input: Option<&[u8]>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        cmd.arg("--module")
            .arg(&module)
            .args(["--format", "json"])
            .args(args)
            .arg("--pin-file")
            .arg(&pin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if input.is_some() {
            cmd.stdin(Stdio::piped());
        }
        let mut child = cmd.spawn().unwrap();
        if let Some(bytes) = input {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        }
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success(), "{args:?}: {result:?}");
        assert!(result.stderr.is_empty());
        result.stdout
    };
    for (name, bytes) in [
        ("plain", b"protected KDF proof".as_slice()),
        ("aad", b"Montgomery KDF test"),
        ("label", b"Montgomery proof"),
        ("context", b"v1"),
    ] {
        std::fs::write(root.join(format!("montgomery-kdf-{name}")), bytes).unwrap();
    }
    for curve in 0..4 {
        for kdf in 0..8 {
            for output in [1, 5] {
                let base = cases::uri(0x4b, curve, 0, "private");
                let key = cases::uri(0x4d, curve, 1, "secret-key");
                let id = format!("d94d{curve:02x}01");
                let peer = root.join(format!("montgomery-kdf-peer-{curve}"));
                let info = root.join("montgomery-kdf-info");
                std::fs::write(&info, cases::info(output)).unwrap();
                let mut args = vec![
                    match curve {
                        0 => "derive-x25519",
                        1 => "derive-x448",
                        _ => "derive-montgomery",
                    },
                    "--object",
                    &base,
                    "--kdf",
                    cases::kdf_name(kdf),
                    "--kind",
                    if output == 1 {
                        "derivation-secret"
                    } else {
                        "aes256"
                    },
                    "--id",
                    &id,
                    "--label",
                    "CLI KDF key",
                    "--confirm",
                    "--shared-info-file",
                    info.to_str().unwrap(),
                    "--input",
                    if kdf % 2 == 0 {
                        "-"
                    } else {
                        peer.to_str().unwrap()
                    },
                ];
                if curve >= 2 {
                    args.extend([
                        "--curve",
                        if curve == 2 { "curve25519" } else { "curve448" },
                    ]);
                }
                if output == 1 {
                    args.extend(["--length", "64"]);
                }
                let bytes = cases::peer_input(curve);
                let result: serde_json::Value = serde_json::from_slice(&run(
                    &args,
                    if kdf % 2 == 0 { Some(&bytes) } else { None },
                ))
                .unwrap();
                assert_eq!(
                    result["result"]["length"],
                    if output == 1 { 64 } else { 32 }
                );
                assert_eq!(result["result"]["extractable"], false);
                let proof = cases::uri(0x4d, curve, 2, "secret-key");
                let proof_id = format!("d94d{curve:02x}02");
                if output == 1 {
                    run(
                        &[
                            "derive-kbkdf",
                            "--object",
                            &key,
                            "--digest",
                            "sha512",
                            "--kind",
                            "aes256",
                            "--id",
                            &proof_id,
                            "--label",
                            "CLI KDF proof",
                            "--confirm",
                            "--kdf-label-file",
                            root.join("montgomery-kdf-label").to_str().unwrap(),
                            "--kdf-context-file",
                            root.join("montgomery-kdf-context").to_str().unwrap(),
                        ],
                        None,
                    );
                }
                let cipher = run(
                    &[
                        "encrypt-aes-gcm",
                        "--object",
                        if output == 1 { &proof } else { &key },
                        "--nonce",
                        "060606060606060606060606",
                        "--aad-file",
                        root.join("montgomery-kdf-aad").to_str().unwrap(),
                        "--input",
                        root.join("montgomery-kdf-plain").to_str().unwrap(),
                        "--output",
                        "-",
                    ],
                    None,
                );
                assert_eq!(
                    cipher,
                    std::fs::read(root.join(cases::cipher_name(curve, kdf, output))).unwrap(),
                    "{curve}/{kdf}/{output}"
                );
                if output == 1 {
                    run(&["delete", "--object", &proof, "--confirm"], None);
                }
                run(&["delete", "--object", &key, "--confirm"], None);
            }
        }
    }
}
