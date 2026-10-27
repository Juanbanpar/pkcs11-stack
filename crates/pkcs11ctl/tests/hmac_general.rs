// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native general HMAC CLI output, length and permission contracts.
use serde_json::Value;
use std::{path::PathBuf, process::Command};
#[test]
#[ignore = "requires disposable Kryoptic runner after runtime HMAC fixtures"]
fn general_hmac_cli_native_tags_lengths_and_file_contracts() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = std::env::var("PKCS11_TEST_KDF_MODULE").unwrap();
    let root =
        PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap()).join("cli-hmac-general");
    std::fs::create_dir(&root).unwrap();
    let pin = root.join("pin");
    std::fs::write(&pin, b"12345678").unwrap();
    let message = root.join("message");
    std::fs::write(&message, b"general CLI HMAC").unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args(["--module", &module, "--format", "json"])
            .args(args)
            .args(["--pin-file", pin.to_str().unwrap()])
            .output()
            .unwrap()
    };
    for (index, (algorithm, full)) in [
        ("hmac-sha256", 32),
        ("hmac-sha384", 48),
        ("hmac-sha512", 64),
        ("hmac-sha224", 28),
        ("hmac-sha512-224", 28),
        ("hmac-sha512-256", 32),
        ("hmac-sha3-224", 28),
        ("hmac-sha3-256", 32),
        ("hmac-sha3-384", 48),
        ("hmac-sha3-512", 64),
    ]
    .into_iter()
    .enumerate()
    {
        let uri = format!(
            "pkcs11:token=kdf-test;object=hmac-vector-{index}-false-{full};type=secret-key"
        );
        let caps = run(&[
            "hmac-capabilities",
            "--object",
            &uri,
            "--operation",
            "generate",
            "--general-tag",
        ]);
        assert!(
            caps.status.success(),
            "{}",
            String::from_utf8_lossy(&caps.stderr)
        );
        let caps: Value = serde_json::from_slice(&caps.stdout).unwrap();
        assert_eq!(caps["result"]["general_tag"], true);
        assert_eq!(caps["result"]["algorithms"].as_array().unwrap().len(), 10);
        let expected = Command::new(std::env::var("PKCS11_TEST_KDF_OPENSSL").unwrap())
            .args([
                "dgst",
                &format!("-{}", algorithm.strip_prefix("hmac-").unwrap()),
                "-mac",
                "HMAC",
                "-macopt",
                &format!("hexkey:{}", "0b".repeat(full)),
                "-binary",
                message.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(expected.status.success());
        for length in [full / 2, full - 1, full] {
            let length_string = length.to_string();
            let tag = root.join(format!("tag-{index}-{length}"));
            let create = [
                "mac-hmac",
                "--object",
                &uri,
                "--algorithm",
                algorithm,
                "--tag-length",
                &length_string,
                "--input",
                message.to_str().unwrap(),
                "--output",
                tag.to_str().unwrap(),
            ];
            let out = run(&create);
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(std::fs::read(&tag).unwrap(), expected.stdout[..length]);
            assert_eq!(run(&create).status.code(), Some(6));
            assert_eq!(std::fs::read(&tag).unwrap(), expected.stdout[..length]);
            let verify = [
                "verify-hmac",
                "--object",
                &uri,
                "--algorithm",
                algorithm,
                "--tag-length",
                &length_string,
                "--input",
                message.to_str().unwrap(),
                "--tag-file",
                tag.to_str().unwrap(),
            ];
            assert!(run(&verify).status.success());
            std::fs::write(&tag, vec![0; length]).unwrap();
            let out = run(&verify);
            assert_eq!(out.status.code(), Some(4));
            assert!(out.stdout.is_empty());
            std::fs::write(&tag, vec![0; length - 1]).unwrap();
            assert_eq!(run(&verify).status.code(), Some(2));
            let mut stdout = create;
            *stdout.last_mut().unwrap() = "-";
            let out = run(&stdout);
            assert!(out.status.success());
            assert_eq!(out.stdout, expected.stdout[..length]);
        }
        // Provider execution support does not override missing generation bounds.
        let out = run(&[
            "generate",
            "--token",
            "pkcs11:token=kdf-test",
            "--kind",
            algorithm,
            "--general-tag",
            "--id",
            &format!("fa12{index:02x}"),
            "--label",
            "general-hmac",
            "--confirm",
        ]);
        assert_eq!(out.status.code(), Some(4));
        assert!(out.stdout.is_empty());
    }
}
