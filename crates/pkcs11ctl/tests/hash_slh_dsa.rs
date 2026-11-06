// SPDX-License-Identifier: MIT OR Apache-2.0
//! HashSLH-DSA command validation, large signatures and output withheld through cleanup.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/slh_dsa_module.rs"]
mod fixture;
use std::{
    path::Path,
    process::{Command, Output},
};
fn run(module: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .arg("--module")
        .arg(module)
        .args(["--format", "json"])
        .args(args)
        .output()
        .unwrap()
}
fn ok(output: Output) -> Vec<u8> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    output.stdout
}
#[test]
fn native_profiles_large_signatures_context_auth_and_late_failures() {
    for (parameter, name) in [(0, "slh-dsa-sha2-128s"), (11, "slh-dsa-shake-256f")] {
        for prehash in [false, true] {
            for fault in [0, 5, 6, 9, 11, 12, 15, 16, 17, 18, 19, 20, 21, 26, 27] {
                let fixture = fixture::SlhDsaModule::hash(
                    (3, 2),
                    parameter,
                    fault,
                    true,
                    (1, 3),
                    (3, prehash),
                );
                let root = fixture.path().parent().unwrap().to_path_buf();
                let input = root.join("message");
                let context = root.join("context");
                let pin = root.join("pin");
                let output = root.join("signature");
                std::fs::write(
                    &input,
                    if prehash {
                        &[0xc7; 64]
                    } else {
                        b"abc".as_slice()
                    },
                )
                .unwrap();
                std::fs::write(&context, [0xa5; 3]).unwrap();
                std::fs::write(&pin, b"12345678").unwrap();
                let args = [
                    "sign-hash-slh-dsa",
                    "--object",
                    "pkcs11:token=cmac;id=%01;type=private",
                    "--parameter-set",
                    name,
                    "--input",
                    input.to_str().unwrap(),
                    "--context-file",
                    context.to_str().unwrap(),
                    "--context-pin-file",
                    pin.to_str().unwrap(),
                    "--output",
                    output.to_str().unwrap(),
                    "--digest",
                    "sha512",
                    "--input-kind",
                    if prehash { "digest" } else { "message" },
                ];
                let result = run(&fixture.path(), &args);
                if fault == 0 {
                    ok(result);
                    let signature = std::fs::read(&output).unwrap();
                    assert_eq!(
                        signature,
                        vec![0xab; if parameter == 0 { 7856 } else { 49856 }]
                    );
                    let verify = [
                        "verify-hash-slh-dsa",
                        "--object",
                        "pkcs11:token=cmac;id=%01;type=public",
                        "--parameter-set",
                        name,
                        "--input",
                        input.to_str().unwrap(),
                        "--context-file",
                        context.to_str().unwrap(),
                        "--signature",
                        output.to_str().unwrap(),
                        "--digest",
                        "sha512",
                        "--input-kind",
                        if prehash { "digest" } else { "message" },
                    ];
                    ok(run(&fixture.path(), &verify));
                    std::fs::remove_file(&output).unwrap();
                } else {
                    assert!(!result.status.success(), "{parameter}/{fault}");
                    assert!(result.stdout.is_empty());
                    assert!(!output.exists());
                    let error: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
                    assert!(error["error"]["kind"].is_string());
                    if matches!(fault, 26 | 27) {
                        let mut args = args;
                        args[12] = "-";
                        let result = run(&fixture.path(), &args);
                        assert!(!result.status.success());
                        assert!(result.stdout.is_empty());
                    }
                }
                std::fs::write(&output, b"preserve existing output").unwrap();
                assert!(!run(&fixture.path(), &args).status.success());
                assert_eq!(std::fs::read(&output).unwrap(), b"preserve existing output");
            }
        }
    }
}
#[test]
fn invalid_hash_slh_shapes_and_weak_default_are_rejected_before_provider_loading() {
    let fixture = fixture::SlhDsaModule::hash((3, 2), 0, 0, false, (1, 0), (3, true));
    let root = fixture.path().parent().unwrap().to_path_buf();
    let input = root.join("input");
    let signature = root.join("signature");
    let output = root.join("output");
    std::fs::write(&input, [0xc7; 31]).unwrap();
    std::fs::write(&signature, [0; 7856]).unwrap();
    let base = vec![
        "sign-hash-slh-dsa",
        "--object",
        "pkcs11:token=cmac;id=%01;type=private",
        "--parameter-set",
        "slh-dsa-sha2-128s",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ];
    for extra in [
        vec!["--digest", "sha256", "--input-kind", "digest"],
        vec!["--digest", "shake128"],
        vec!["--digest", "sha512", "--multipart"],
        vec![],
    ] {
        let mut args = base.clone();
        args.extend(extra);
        let result = run(Path::new("/missing-hash-slh-provider.so"), &args);
        assert_eq!(
            result.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stdout.is_empty());
        assert!(!output.exists());
    }
    let mut weak = base.clone();
    weak.extend(["--digest", "sha224"]);
    let result = run(Path::new("/missing-hash-slh-provider.so"), &weak);
    assert_eq!(result.status.code(), Some(4));
    assert!(result.stdout.is_empty());
    assert!(!output.exists());
    let dual = [
        "verify-hash-slh-dsa",
        "--object",
        "pkcs11:token=cmac;id=%01;type=public",
        "--parameter-set",
        "slh-dsa-sha2-128s",
        "--digest",
        "sha512",
        "--input",
        "-",
        "--signature",
        "-",
    ];
    assert_eq!(
        run(Path::new("/missing-hash-slh-provider.so"), &dual)
            .status
            .code(),
        Some(2)
    );
}
