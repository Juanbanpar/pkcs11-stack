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
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn cmac_cli_independent_tags_generation_permissions_and_outputs() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let module = std::env::var("PKCS11_TEST_MODULE").unwrap();
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap()).join("cli-cmac");
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
        let uri = format!("pkcs11:token=client-test;object=cmac-vector-{bits};type=secret-key");
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
            "pkcs11:token=client-test",
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
        let uri = format!("pkcs11:token=client-test;object={label};type=secret-key");
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
