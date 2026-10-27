// SPDX-License-Identifier: MIT OR Apache-2.0
//! Counter/feedback CLI preflight and provider workflows.
use serde_json::Value;
use std::process::{Command, Output};
fn run(module: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .args(["--module", module, "--format", "json"])
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn kbkdf_preflight_bounds_class_and_public_files() {
    let root = std::env::temp_dir().join(format!("kbkdf-preflight-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let large = root.join("large");
    std::fs::write(&large, vec![0; 4097]).unwrap();
    let common = [
        "derive-kbkdf",
        "--object",
        "pkcs11:token=test;id=%01;type=secret-key",
        "--digest",
        "sha256",
        "--id",
        "02",
        "--label",
        "output",
        "--confirm",
    ];
    for extra in [
        vec!["--kind", "derivation-secret", "--length", "0"],
        vec!["--kind", "derivation-secret", "--length", "4097"],
        vec!["--kind", "aes256", "--length", "32"],
        vec!["--kind", "aes256", "--kdf-label-file", "-"],
        vec!["--kind", "aes256", "--kdf-context-file", "-"],
        vec![
            "--kind",
            "aes256",
            "--kdf-context-file",
            large.to_str().unwrap(),
        ],
        vec![
            "--kind",
            "aes256",
            "--kdf-label-file",
            large.to_str().unwrap(),
        ],
    ] {
        let mut args = common.to_vec();
        args.extend(extra);
        let result = run("/missing", &args);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
    }
    for kind in ["public", "private"] {
        let uri = format!("pkcs11:token=test;id=%01;type={kind}");
        assert_eq!(
            run("/missing", &["kbkdf-capabilities", "--object", &uri])
                .status
                .code(),
            Some(2)
        );
    }
    let mut args = common.to_vec();
    args.extend(["--kind", "aes256"]);
    assert_eq!(run("/missing", &args).status.code(), Some(5));
    let iv = root.join("iv");
    for (mode, digest, bytes, expected) in [
        ("counter", "sha256", vec![], 2),
        ("counter", "sha256", vec![0; 32], 2),
        ("feedback", "sha256", vec![0; 31], 2),
        ("feedback", "sha384", vec![0; 32], 2),
        ("feedback", "sha512", vec![0; 65], 2),
        ("feedback", "sha256", vec![], 5),
        ("feedback", "sha256", vec![0; 32], 5),
        ("feedback", "sha384", vec![0; 48], 5),
        ("feedback", "sha512", vec![0; 64], 5),
    ] {
        std::fs::write(&iv, bytes).unwrap();
        let mut args = common.to_vec();
        let position = args.iter().position(|arg| *arg == "--digest").unwrap();
        args[position + 1] = digest;
        args.extend([
            "--mode",
            mode,
            "--kind",
            "aes256",
            "--kdf-iv-file",
            iv.to_str().unwrap(),
        ]);
        assert_eq!(run("/missing", &args).status.code(), Some(expected));
    }
    let mut args = common.to_vec();
    args.extend([
        "--mode",
        "feedback",
        "--kind",
        "aes256",
        "--kdf-iv-file",
        "-",
    ]);
    assert_eq!(run("/missing", &args).status.code(), Some(2));
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh SP800-108 provider"]
fn kbkdf_modes_cli_capabilities_derive_and_independent_runtime_agreement() {
    for mode in ["counter", "feedback"] {
        check_mode(mode);
    }
}
fn check_mode(mode: &str) {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = std::env::var("PKCS11_TEST_KDF_MODULE").unwrap();
    let root = std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap())
        .join(format!("cli-kbkdf-{mode}"));
    std::fs::create_dir(&root).unwrap();
    let pin = root.join("pin");
    std::fs::write(&pin, b"12345678\n").unwrap();
    let label = root.join("label");
    std::fs::write(&label, b"application").unwrap();
    let context = root.join("context");
    std::fs::write(&context, b"v1 context").unwrap();
    let plaintext = root.join("plain");
    std::fs::write(&plaintext, b"CLI counter agreement").unwrap();
    let iv_file = root.join("iv");
    let invoke = |args: &[&str]| {
        let mut args = args.to_vec();
        if mode == "feedback" && matches!(args[0], "kbkdf-capabilities" | "derive-kbkdf") {
            args.extend(["--mode", mode]);
        }
        if args[0] == "derive-kbkdf" && mode == "feedback" {
            args.extend(["--kdf-iv-file", iv_file.to_str().unwrap()]);
        }
        args.extend(["--pin-file", pin.to_str().unwrap()]);
        run(&module, &args)
    };
    let ok = |args: &[&str]| {
        let out = invoke(args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        if out.stdout.is_empty() {
            return Value::Null;
        }
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["result"].clone()
    };
    for (index, digest) in ["sha256", "sha384", "sha512"].into_iter().enumerate() {
        std::fs::write(&iv_file, vec![0xA5; [32, 48, 64][index]]).unwrap();
        let base = format!("pkcs11:token=kdf-test;id=%A0%{index:02X};type=secret-key");
        let caps = ok(&["kbkdf-capabilities", "--object", &base]);
        assert_eq!(
            caps["digests"],
            serde_json::json!(["sha256", "sha384", "sha512"])
        );
        assert_eq!(caps["mode"], mode);
        let id = format!("fa88{index:02x}");
        let object = format!("pkcs11:token=kdf-test;id=%FA%88%{index:02X};type=secret-key");
        let canonical = format!(
            "pkcs11:token=kdf-test;id=%FA%{:02X}%{index:02X};type=secret-key",
            if mode == "counter" { 0x82 } else { 0x8A }
        );
        let args = [
            "derive-kbkdf",
            "--object",
            &base,
            "--digest",
            digest,
            "--kind",
            "aes256",
            "--kdf-label-file",
            label.to_str().unwrap(),
            "--kdf-context-file",
            context.to_str().unwrap(),
            "--id",
            &id,
            "--label",
            "CLI counter AES",
            "--confirm",
        ];
        let result = ok(&args);
        assert_eq!(result["derived"], true);
        assert_eq!(result["mode"], mode);
        assert_eq!(result["extractable"], false);
        assert_eq!(result["length"], 32);
        assert_eq!(invoke(&args).status.code(), Some(2));
        let cipher = root.join(format!("cipher-{index}"));
        let recovered = root.join(format!("recovered-{index}"));
        let nonce = format!("{index:02x}").repeat(12);
        ok(&[
            "encrypt-aes-gcm",
            "--object",
            &object,
            "--nonce",
            &nonce,
            "--input",
            plaintext.to_str().unwrap(),
            "--output",
            cipher.to_str().unwrap(),
        ]);
        ok(&[
            "decrypt-aes-gcm",
            "--object",
            &canonical,
            "--nonce",
            &nonce,
            "--input",
            cipher.to_str().unwrap(),
            "--output",
            recovered.to_str().unwrap(),
        ]);
        assert_eq!(std::fs::read(recovered).unwrap(), b"CLI counter agreement");
        let blocked = invoke(&[
            "derive-kbkdf",
            "--object",
            &canonical,
            "--digest",
            digest,
            "--kind",
            "aes256",
            "--id",
            "fa88ff",
            "--label",
            "blocked",
            "--confirm",
        ]);
        assert_eq!(blocked.status.code(), Some(4));
        assert!(blocked.stdout.is_empty());
        ok(&["delete", "--object", &object, "--confirm"]);
    }
}
