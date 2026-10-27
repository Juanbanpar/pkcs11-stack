// SPDX-License-Identifier: MIT OR Apache-2.0
//! HMAC CLI preflight and independent provider comparisons.
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
fn hmac_preflight_rejects_shapes_before_loading() {
    let root = std::env::temp_dir().join(format!("pkcs11-hmac-cli-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let tag = root.join("tag");
    let tag = tag.to_str().unwrap();
    for (algorithm, length) in [
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
    ] {
        for bad in [0, length - 1, length + 1] {
            std::fs::write(tag, vec![0; bad]).unwrap();
            let out = run(
                "/missing",
                &[
                    "verify-hmac",
                    "--object",
                    "pkcs11:token=test;id=%01;type=secret-key",
                    "--algorithm",
                    algorithm,
                    "--input",
                    "missing-message",
                    "--tag-file",
                    tag,
                ],
            );
            assert_eq!(out.status.code(), Some(2));
            assert!(out.stdout.is_empty());
        }
    }
    for kind in ["public", "private"] {
        let uri = format!("pkcs11:token=test;id=%01;type={kind}");
        assert_eq!(
            run(
                "/missing",
                &[
                    "hmac-capabilities",
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
    for extra in ["--always-authenticate", "--purpose"] {
        let mut args = vec![
            "generate",
            "--token",
            "pkcs11:token=test",
            "--kind",
            "hmac-sha256",
            "--id",
            "01",
            "--label",
            "key",
            "--confirm",
            extra,
        ];
        if extra == "--purpose" {
            args.push("authentication");
        }
        assert_eq!(run("/missing", &args).status.code(), Some(2));
    }
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn hmac_cli_independent_tags_purpose_and_output_contracts() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let module = std::env::var("PKCS11_TEST_MODULE").unwrap();
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap()).join("cli-hmac");
    std::fs::create_dir(&root).unwrap();
    let pin = root.join("pin");
    std::fs::write(&pin, b"12345678\n").unwrap();
    let message = root.join("message");
    std::fs::write(&message, b"CLI HMAC input").unwrap();
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
    let options: Value = serde_json::from_slice(
        &run(
            &module,
            &["generation-options", "--token", "pkcs11:token=client-test"],
        )
        .stdout,
    )
    .unwrap();
    let algorithms = options["result"]["hmac"].as_array().unwrap();
    for (index, (algorithm, length)) in [
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
        if !algorithms.iter().any(|a| a == algorithm) {
            continue;
        }
        let uri = format!(
            "pkcs11:token=client-test;object=hmac-vector-{index}-false-{length};type=secret-key"
        );
        let caps: Value = serde_json::from_slice(
            &ok(&[
                "hmac-capabilities",
                "--object",
                &uri,
                "--operation",
                "generate",
            ])
            .stdout,
        )
        .unwrap();
        assert_eq!(caps["result"]["key_length"], length);
        assert_eq!(caps["result"]["algorithms"], options["result"]["hmac"]);
        let tag = root.join(format!("tag-{index}"));
        let create = [
            "mac-hmac",
            "--object",
            &uri,
            "--algorithm",
            algorithm,
            "--input",
            message.to_str().unwrap(),
            "--output",
            tag.to_str().unwrap(),
        ];
        ok(&create);
        let expected = Command::new("openssl")
            .args([
                "dgst",
                &format!("-{}", algorithm.strip_prefix("hmac-").unwrap()),
                "-mac",
                "HMAC",
                "-macopt",
                &format!("hexkey:{}", "0b".repeat(length)),
                "-binary",
                message.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(expected.status.success());
        assert_eq!(std::fs::read(&tag).unwrap(), expected.stdout);
        assert_eq!(invoke(&create).status.code(), Some(6));
        assert_eq!(std::fs::read(&tag).unwrap(), expected.stdout);
        let verify = [
            "verify-hmac",
            "--object",
            &uri,
            "--algorithm",
            algorithm,
            "--input",
            message.to_str().unwrap(),
            "--tag-file",
            tag.to_str().unwrap(),
        ];
        ok(&verify);
        std::fs::write(&tag, vec![0; length]).unwrap();
        let out = invoke(&verify);
        assert_eq!(out.status.code(), Some(4));
        assert!(out.stdout.is_empty());
        let label = format!("cli-hmac-{index}");
        let id = format!("f648{index:02x}");
        ok(&[
            "generate",
            "--token",
            "pkcs11:token=client-test",
            "--kind",
            algorithm,
            "--id",
            &id,
            "--label",
            &label,
            "--confirm",
        ]);
        let uri = format!("pkcs11:token=client-test;object={label};type=secret-key");
        let result = ok(&[
            "mac-hmac",
            "--object",
            &uri,
            "--algorithm",
            algorithm,
            "--input",
            message.to_str().unwrap(),
            "--output",
            "-",
        ]);
        assert_eq!(result.stdout.len(), length);
        let caps: Value = serde_json::from_slice(
            &ok(&[
                "hmac-capabilities",
                "--object",
                &uri,
                "--operation",
                "verify",
            ])
            .stdout,
        )
        .unwrap();
        assert_eq!(caps["result"]["algorithms"], serde_json::json!([algorithm]));
    }
}
