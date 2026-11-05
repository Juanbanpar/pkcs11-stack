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
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command
            .args(["--module", &module, "--format", "json"])
            .args(args);
        if args[0] != "generation-options" {
            command.args(["--pin-file", pin.to_str().unwrap()]);
        }
        command.output().unwrap()
    };
    let proof = root.join("generated-message");
    std::fs::write(&proof, b"generated general HMAC\0\xff").unwrap();
    let options = run(&["generation-options", "--token", "pkcs11:token=kdf-test"]);
    assert!(
        options.status.success(),
        "{}",
        String::from_utf8_lossy(&options.stderr)
    );
    let options: Value = serde_json::from_slice(&options.stdout).unwrap();
    assert_eq!(
        options["result"]["hmac_general"].as_array().unwrap().len(),
        10
    );
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
        let id = format!("fa12{index:02x}");
        let label = format!("cli-hmac-generated-general-{index}");
        let create = [
            "generate",
            "--token",
            "pkcs11:token=kdf-test",
            "--kind",
            algorithm,
            "--general-tag",
            "--id",
            &id,
            "--label",
            &label,
            "--confirm",
        ];
        let out = run(&create);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let generated: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(generated["result"]["generated"], true);
        assert_eq!(generated["result"]["key"]["general_tag"], true);
        assert_eq!(generated["result"]["extractable"], false);
        assert_eq!(run(&create).status.code(), Some(2));
        let own = format!("pkcs11:token=kdf-test;object={label};type=secret-key");
        let canonical =
            format!("pkcs11:token=kdf-test;object=hmac-generated-general-{index};type=secret-key");
        for (case, key) in [&own, &canonical].into_iter().enumerate() {
            let caps = run(&[
                "hmac-capabilities",
                "--object",
                key,
                "--operation",
                "generate",
                "--general-tag",
            ]);
            assert!(caps.status.success());
            let caps: Value = serde_json::from_slice(&caps.stdout).unwrap();
            assert_eq!(caps["result"]["algorithms"], serde_json::json!([algorithm]));
            let length = (full / 2).to_string();
            let mac = [
                "mac-hmac",
                "--object",
                key,
                "--algorithm",
                algorithm,
                "--tag-length",
                &length,
                "--input",
                proof.to_str().unwrap(),
                "--output",
                "-",
            ];
            let tag = run(&mac);
            assert!(tag.status.success());
            assert_eq!(tag.stdout.len(), full / 2);
            if case == 1 {
                let reference = root
                    .parent()
                    .unwrap()
                    .join(format!("hmac-generated-general-{index}.tag"));
                assert_eq!(tag.stdout, std::fs::read(reference).unwrap());
            }
            let mut stream = mac.to_vec();
            stream.push("--multipart");
            let streamed = run(&stream);
            assert!(streamed.status.success());
            assert_eq!(streamed.stdout, tag.stdout);
            let tag_file = root.join(format!("generated-{index}-{case}.tag"));
            std::fs::write(&tag_file, &tag.stdout).unwrap();
            let verify = [
                "verify-hmac",
                "--object",
                key,
                "--algorithm",
                algorithm,
                "--tag-length",
                &length,
                "--input",
                proof.to_str().unwrap(),
                "--tag-file",
                tag_file.to_str().unwrap(),
            ];
            assert!(run(&verify).status.success());
            let mut bad = tag.stdout;
            bad[0] ^= 1;
            std::fs::write(&tag_file, bad).unwrap();
            let mismatch = run(&verify);
            assert_eq!(mismatch.status.code(), Some(4));
            assert!(mismatch.stdout.is_empty());
            let blocked = run(&[
                "mac-hmac",
                "--object",
                key,
                "--algorithm",
                algorithm,
                "--input",
                proof.to_str().unwrap(),
                "--output",
                "-",
            ]);
            assert_eq!(blocked.status.code(), Some(4));
            assert!(blocked.stdout.is_empty());
        }
        assert!(
            run(&["delete", "--object", &own, "--confirm"])
                .status
                .success()
        );
    }
}
