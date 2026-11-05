// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit message API selection and authenticated output after checked cleanup.
use serde_json::Value;
use std::{
    path::Path,
    process::{Command, Output},
};
#[cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod fixture;
fn run(module: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .arg("--module")
        .arg(module)
        .args(["--format", "json"])
        .args(args)
        .output()
        .unwrap()
}
fn success(output: Output) -> Vec<u8> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    output.stdout
}
#[cfg(unix)]
#[test]
fn native_mode_selection_failure_cleanup_and_preserved_outputs() {
    let object = "pkcs11:token=cmac;id=%01;type=secret-key";
    for headers in ["2.40", "3.0", "3.1", "3.2"] {
        let faults = if headers == "3.2" {
            vec![0, 3, 4, 5, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 29, 30]
        } else {
            vec![0]
        };
        for fault in faults {
            let fixture =
                fixture::MetadataModule::with_headers("aes_gcm_message.c", fault, headers);
            let root = fixture.path().parent().unwrap();
            let aad = root.join("aad");
            let plain = root.join("plain");
            let cipher = root.join("cipher");
            let output = root.join("output");
            std::fs::write(&aad, b"\0\xff").unwrap();
            std::fs::write(&plain, b"abc").unwrap();
            let mut ciphertext = vec![0xe1, 0xe2, 0xe3];
            ciphertext.extend([0xef; 16]);
            std::fs::write(&cipher, &ciphertext).unwrap();
            for decrypt in [false, true] {
                let args = [
                    if decrypt {
                        "decrypt-aes-gcm"
                    } else {
                        "encrypt-aes-gcm"
                    },
                    "--message-api",
                    "--object",
                    object,
                    "--nonce",
                    "a5a5a5a5a5a5a5a5a5a5a5a5",
                    "--aad-file",
                    aad.to_str().unwrap(),
                    "--input",
                    if decrypt {
                        cipher.to_str().unwrap()
                    } else {
                        plain.to_str().unwrap()
                    },
                    "--output",
                    output.to_str().unwrap(),
                ];
                let result = run(fixture.path(), &args);
                let valid = headers != "2.40"
                    && (fault == 0
                        || (decrypt && matches!(fault, 3..=5))
                        || (!decrypt && fault == 15));
                if valid {
                    success(result);
                    assert_eq!(
                        std::fs::read(&output).unwrap(),
                        if decrypt {
                            b"abc".to_vec()
                        } else {
                            ciphertext.clone()
                        }
                    );
                    std::fs::remove_file(&output).unwrap();
                } else {
                    assert!(!result.status.success(), "{headers}/{fault}/{decrypt}");
                    assert!(result.stdout.is_empty());
                    assert!(!output.exists());
                    let error: Value = serde_json::from_slice(&result.stderr).unwrap();
                    assert!(error["error"]["kind"].is_string());
                    assert!(!String::from_utf8_lossy(&result.stderr).contains("abc"));
                }
                if matches!(fault, 16 | 29 | 30) {
                    let mut stdout_args = args;
                    stdout_args[11] = "-";
                    let failed = run(fixture.path(), &stdout_args);
                    assert!(!failed.status.success());
                    assert!(
                        failed.stdout.is_empty(),
                        "late failure released binary output"
                    );
                }
                std::fs::write(&output, b"keep existing output").unwrap();
                assert!(!run(fixture.path(), &args).status.success());
                assert_eq!(std::fs::read(&output).unwrap(), b"keep existing output");
                std::fs::remove_file(&output).unwrap();
            }
        }
    }
    let fixture = fixture::MetadataModule::from_source("aes_gcm_message.c", 0);
    let caps: Value = serde_json::from_slice(&success(run(
        fixture.path(),
        &[
            "aes-gcm-capabilities",
            "--message-api",
            "--object",
            object,
            "--operation",
            "encrypt",
        ],
    )))
    .unwrap();
    assert_eq!(caps["result"]["message_api"], true);
    assert_eq!(caps["result"]["multipart"], false);
    assert!(
        !run(
            fixture.path(),
            &[
                "aes-gcm-capabilities",
                "--object",
                object,
                "--operation",
                "encrypt"
            ]
        )
        .status
        .success()
    );
    let conflict = run(
        fixture.path(),
        &[
            "aes-gcm-capabilities",
            "--message-api",
            "--multipart",
            "--object",
            object,
            "--operation",
            "encrypt",
        ],
    );
    assert_eq!(conflict.status.code(), Some(2));
}
#[test]
#[ignore = "requires tools/test-nss.sh after runtime message fixtures"]
fn nss_cli_protected_keys_and_runtime_agreement() {
    assert_eq!(
        std::env::var("PKCS11_TEST_NSS_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap());
    let pin = root.join("pin");
    let aad = root.join("gcm-message-cli-aad");
    let input = root.join("gcm-message-cli-input");
    std::fs::write(&aad, b"binary\0\xff").unwrap();
    std::fs::write(&input, b"generated message canary").unwrap();
    for index in 0..3 {
        let label = format!("gcm-message-generated-{index}");
        let object = format!("pkcs11:token=kdf-test;object={label};type=secret-key");
        let canonical = root.join(format!("{label}.ciphertext"));
        let out = root.join(format!("gcm-message-cli-{index}"));
        let cipher = root.join(format!("gcm-message-cli-{index}.cipher"));
        let caps: Value = serde_json::from_slice(&success(run(
            &module,
            &[
                "aes-gcm-capabilities",
                "--message-api",
                "--object",
                &object,
                "--operation",
                "encrypt",
                "--pin-file",
                pin.to_str().unwrap(),
            ],
        )))
        .unwrap();
        assert_eq!(caps["result"]["key_bits"], (16 + index * 8) * 8);
        assert_eq!(caps["result"]["message_api"], true);
        success(run(
            &module,
            &[
                "decrypt-aes-gcm",
                "--message-api",
                "--object",
                &object,
                "--nonce",
                "424242424242424242424242",
                "--aad-file",
                aad.to_str().unwrap(),
                "--input",
                canonical.to_str().unwrap(),
                "--output",
                out.to_str().unwrap(),
                "--pin-file",
                pin.to_str().unwrap(),
            ],
        ));
        assert_eq!(std::fs::read(&out).unwrap(), b"generated message canary");
        std::fs::remove_file(&out).unwrap();
        success(run(
            &module,
            &[
                "encrypt-aes-gcm",
                "--message-api",
                "--object",
                &object,
                "--nonce",
                "606060606060606060606060",
                "--aad-file",
                aad.to_str().unwrap(),
                "--input",
                input.to_str().unwrap(),
                "--output",
                cipher.to_str().unwrap(),
                "--pin-file",
                pin.to_str().unwrap(),
            ],
        ));
        // Ordinary decryption consumes the same ciphertext || tag transport.
        success(run(
            &module,
            &[
                "decrypt-aes-gcm",
                "--object",
                &object,
                "--nonce",
                "606060606060606060606060",
                "--aad-file",
                aad.to_str().unwrap(),
                "--input",
                cipher.to_str().unwrap(),
                "--output",
                out.to_str().unwrap(),
                "--pin-file",
                pin.to_str().unwrap(),
            ],
        ));
        assert_eq!(std::fs::read(&out).unwrap(), b"generated message canary");
        std::fs::remove_file(&out).unwrap();
        let mut bad = std::fs::read(&canonical).unwrap();
        bad[0] ^= 1;
        let tampered = root.join(format!("gcm-message-cli-{index}.bad"));
        std::fs::write(&tampered, bad).unwrap();
        let result = run(
            &module,
            &[
                "decrypt-aes-gcm",
                "--message-api",
                "--object",
                &object,
                "--nonce",
                "424242424242424242424242",
                "--aad-file",
                aad.to_str().unwrap(),
                "--input",
                tampered.to_str().unwrap(),
                "--output",
                out.to_str().unwrap(),
                "--pin-file",
                pin.to_str().unwrap(),
            ],
        );
        assert_eq!(result.status.code(), Some(5));
        assert!(result.stdout.is_empty());
        assert!(!out.exists());
    }
}
