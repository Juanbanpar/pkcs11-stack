// SPDX-License-Identifier: MIT OR Apache-2.0
//! AES-CMAC preflight, provider and output contracts.
use serde_json::Value;
use std::{
    path::PathBuf,
    process::{Command, Output},
};
fn run(module: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .args(["--module", module, "--format", "json"])
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn cmac_preflight_rejects_wrong_types_and_tag_lengths() {
    let root = std::env::temp_dir().join(format!("pkcs11-cmac-cli-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let message = root.join("message");
    let tag = root.join("tag");
    std::fs::write(&message, b"message").unwrap();
    for length in [0, 15, 17] {
        std::fs::write(&tag, vec![0; length]).unwrap();
        let out = run(
            "/missing",
            &[
                "verify-aes-cmac",
                "--object",
                "pkcs11:token=test;id=%01;type=secret-key",
                "--input",
                message.to_str().unwrap(),
                "--tag-file",
                tag.to_str().unwrap(),
            ],
        );
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
    for kind in ["private", "public"] {
        let uri = format!("pkcs11:token=test;id=%01;type={kind}");
        assert_eq!(
            run(
                "/missing",
                &[
                    "aes-cmac-capabilities",
                    "--object",
                    &uri,
                    "--operation",
                    "generate"
                ]
            )
            .status
            .code(),
            Some(2)
        );
    }
    for length in ["0", "7", "17", "999999999999999999999999"] {
        let out = run(
            "/missing",
            &[
                "mac-aes-cmac",
                "--object",
                "pkcs11:token=test;id=%01;type=secret-key",
                "--input",
                message.to_str().unwrap(),
                "--output",
                "-",
                "--tag-length",
                length,
            ],
        );
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
    for length in 8..=16 {
        let length_arg = length.to_string();
        for actual in [length - 1, length, length + 1] {
            std::fs::write(&tag, vec![0; actual]).unwrap();
            let out = run(
                "/missing",
                &[
                    "verify-aes-cmac",
                    "--object",
                    "pkcs11:token=test;id=%01;type=secret-key",
                    "--input",
                    message.to_str().unwrap(),
                    "--tag-file",
                    tag.to_str().unwrap(),
                    "--tag-length",
                    &length_arg,
                ],
            );
            assert_eq!(
                out.status.code(),
                Some(if actual == length { 5 } else { 2 })
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn cmac_cli_independent_tags_generation_permissions_and_outputs() {
    let general_supported = std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref() == Ok("1");
    assert!(general_supported || std::env::var("PKCS11_TEST_ISOLATED").as_deref() == Ok("1"));
    let token_label = if general_supported {
        "kdf-test"
    } else {
        "client-test"
    };
    let token_uri = format!("pkcs11:token={token_label}");
    let module = std::env::var(if general_supported {
        "PKCS11_TEST_KDF_MODULE"
    } else {
        "PKCS11_TEST_MODULE"
    })
    .unwrap();
    let root = PathBuf::from(
        std::env::var_os(if general_supported {
            "PKCS11_TEST_KDF_DIR"
        } else {
            "PKCS11_CLIENT_TEST_DIR"
        })
        .unwrap(),
    )
    .join("cli-cmac");
    std::fs::create_dir(&root).unwrap();
    let pin = root.join("pin");
    std::fs::write(&pin, b"12345678\n").unwrap();
    let invoke = |args: &[&str]| {
        let mut all = args.to_vec();
        all.extend(["--pin-file", pin.to_str().unwrap()]);
        run(&module, &all)
    };
    let ok = |args: &[&str]| {
        let out = invoke(args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };
    let message = root.join("message");
    std::fs::write(&message, b"CMAC CLI input").unwrap();
    for (index, bits) in [128, 192, 256].into_iter().enumerate() {
        let uri = format!("pkcs11:token={token_label};object=cmac-vector-{bits};type=secret-key");
        let caps: Value = serde_json::from_slice(
            &ok(&[
                "aes-cmac-capabilities",
                "--object",
                &uri,
                "--operation",
                "generate",
            ])
            .stdout,
        )
        .unwrap();
        assert_eq!(caps["result"]["tag_length"], 16);
        let tag = root.join(format!("tag-{bits}"));
        let args = [
            "mac-aes-cmac",
            "--object",
            &uri,
            "--input",
            message.to_str().unwrap(),
            "--output",
            tag.to_str().unwrap(),
        ];
        ok(&args);
        let expected = Command::new("openssl")
            .args([
                "mac",
                "-macopt",
                &format!("cipher:AES-{bits}-CBC"),
                "-macopt",
                &format!("hexkey:{}", "42".repeat(bits / 8)),
                "-in",
                message.to_str().unwrap(),
                "-binary",
                "CMAC",
            ])
            .output()
            .unwrap();
        assert!(expected.status.success());
        assert_eq!(std::fs::read(&tag).unwrap(), expected.stdout);
        for tag_length in (8..=16).filter(|_| general_supported) {
            let length = tag_length.to_string();
            let path = root.join(format!("general-tag-{bits}-{tag_length}"));
            let caps: Value = serde_json::from_slice(
                &ok(&[
                    "aes-cmac-capabilities",
                    "--object",
                    &uri,
                    "--operation",
                    "generate",
                    "--tag-length",
                    &length,
                ])
                .stdout,
            )
            .unwrap();
            assert_eq!(caps["result"]["tag_length"], tag_length);
            let args = [
                "mac-aes-cmac",
                "--object",
                &uri,
                "--input",
                message.to_str().unwrap(),
                "--output",
                path.to_str().unwrap(),
                "--tag-length",
                &length,
            ];
            ok(&args);
            assert_eq!(std::fs::read(&path).unwrap(), expected.stdout[..tag_length]);
            let verify = [
                "verify-aes-cmac",
                "--object",
                &uri,
                "--input",
                message.to_str().unwrap(),
                "--tag-file",
                path.to_str().unwrap(),
                "--tag-length",
                &length,
            ];
            ok(&verify);
            assert_eq!(invoke(&args).status.code(), Some(6));
            assert_eq!(std::fs::read(&path).unwrap(), expected.stdout[..tag_length]);
            std::fs::write(&path, vec![0; tag_length]).unwrap();
            assert_eq!(invoke(&verify).status.code(), Some(4));
        }
        assert_eq!(invoke(&args).status.code(), Some(6));
        assert_eq!(std::fs::read(&tag).unwrap(), expected.stdout);
        let verify = [
            "verify-aes-cmac",
            "--object",
            &uri,
            "--input",
            message.to_str().unwrap(),
            "--tag-file",
            tag.to_str().unwrap(),
        ];
        ok(&verify);
        std::fs::write(&tag, [0; 16]).unwrap();
        let out = invoke(&verify);
        assert_eq!(out.status.code(), Some(4));
        assert!(out.stdout.is_empty());
        let id = format!("f643{index:02x}");
        let label = format!("cli-cmac-generated-{bits}");
        let kind = format!("aes{bits}");
        ok(&[
            "generate",
            "--token",
            &token_uri,
            "--kind",
            &kind,
            "--purpose",
            "authentication",
            "--id",
            &id,
            "--label",
            &label,
            "--confirm",
        ]);
        let uri = format!("pkcs11:token={token_label};object={label};type=secret-key");
        let blocked = invoke(&[
            "mac-aes-cmac",
            "--object",
            &uri,
            "--input",
            message.to_str().unwrap(),
            "--output",
            "-",
            "--tag-length",
            "8",
        ]);
        assert_eq!(blocked.status.code(), Some(4));
        assert!(blocked.stdout.is_empty());
        if general_supported {
            let general_label = format!("cli-cmac-general-{bits}");
            let general_id = format!("f644{index:02x}");
            ok(&[
                "generate",
                "--token",
                &token_uri,
                "--kind",
                &kind,
                "--purpose",
                "authentication-general",
                "--id",
                &general_id,
                "--label",
                &general_label,
                "--confirm",
            ]);
            let general_uri =
                format!("pkcs11:token={token_label};object={general_label};type=secret-key");
            let general_tag = root.join(format!("generated-general-{bits}"));
            ok(&[
                "mac-aes-cmac",
                "--object",
                &general_uri,
                "--input",
                message.to_str().unwrap(),
                "--output",
                general_tag.to_str().unwrap(),
                "--tag-length",
                "8",
            ]);
            assert_eq!(std::fs::read(&general_tag).unwrap().len(), 8);
            ok(&[
                "verify-aes-cmac",
                "--object",
                &general_uri,
                "--input",
                message.to_str().unwrap(),
                "--tag-file",
                general_tag.to_str().unwrap(),
                "--tag-length",
                "8",
            ]);
            let blocked = invoke(&[
                "mac-aes-cmac",
                "--object",
                &general_uri,
                "--input",
                message.to_str().unwrap(),
                "--output",
                "-",
            ]);
            assert_eq!(blocked.status.code(), Some(4));
            assert!(blocked.stdout.is_empty());
            ok(&["delete", "--object", &general_uri, "--confirm"]);
        }
        let raw = ok(&[
            "mac-aes-cmac",
            "--object",
            &uri,
            "--input",
            message.to_str().unwrap(),
            "--output",
            "-",
        ]);
        assert_eq!(raw.stdout.len(), 16);
        assert_eq!(
            invoke(&[
                "aes-gcm-capabilities",
                "--object",
                &uri,
                "--operation",
                "encrypt"
            ])
            .status
            .code(),
            Some(4)
        );
    }
}
