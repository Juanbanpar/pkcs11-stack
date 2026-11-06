// SPDX-License-Identifier: MIT OR Apache-2.0
//! HashSLH-DSA CLI signatures agree with independent runtime reference signatures.
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
fn ok(out: Output) -> Vec<u8> {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty());
    out.stdout
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh after the SLH-DSA runtime test"]
fn cli_hash_slh_dsa_input_modes_stdin_generation_and_runtime_agreement() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let pin = root.join("hslh-cli.pin");
    std::fs::write(&pin, b"12345678").unwrap();
    let input = root.join("hslh-cli.message");
    std::fs::write(&input, b"HashSLH-DSA original message\0\xff").unwrap();
    let context = root.join("hslh-cli.context");
    std::fs::write(&context, b"domain").unwrap();
    let run = |args: &[&str], stdin: Option<&[u8]>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        cmd.arg("--module")
            .arg(&module)
            .args(["--format", "json"])
            .args(args);
        cmd.arg("--pin-file").arg(&pin);
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        if let Some(bytes) = stdin {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        }
        child.wait_with_output().unwrap()
    };
    let names = [
        "slh-dsa-sha2-128s",
        "slh-dsa-sha2-128f",
        "slh-dsa-sha2-192s",
        "slh-dsa-sha2-192f",
        "slh-dsa-sha2-256s",
        "slh-dsa-sha2-256f",
        "slh-dsa-shake-128s",
        "slh-dsa-shake-128f",
        "slh-dsa-shake-192s",
        "slh-dsa-shake-192f",
        "slh-dsa-shake-256s",
        "slh-dsa-shake-256f",
    ];
    for (index, name) in names.into_iter().enumerate() {
        let private =
            format!("pkcs11:token=kdf-test;object=hash-slh-dsa-runtime-{index};type=private");
        let public = private.replace("type=private", "type=public");
        let signature = root.join(format!("hslh-cli-{index}.signature"));
        let hash = [
            "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512",
        ][index % 8];
        let expected = std::fs::read(root.join(format!("hslh-{index}-0.signature"))).unwrap();
        let caps: serde_json::Value = serde_json::from_slice(&ok(run(
            &[
                "hash-slh-dsa-capabilities",
                "--object",
                &private,
                "--digest",
                hash,
            ],
            None,
        )))
        .unwrap();
        assert_eq!(caps["result"]["parameter_set"], name);
        assert_eq!(caps["result"]["can_sign"], true);
        let mut args = vec![
            "sign-hash-slh-dsa",
            "--object",
            &private,
            "--parameter-set",
            name,
            "--input",
            input.to_str().unwrap(),
            "--context-file",
            context.to_str().unwrap(),
            "--hedging",
            "deterministic",
            "--output",
            signature.to_str().unwrap(),
            "--digest",
            hash,
            "--allow-reduced-strength",
        ];
        if index == 1 {
            args.extend(["--context-pin-file", pin.to_str().unwrap()]);
        }
        ok(run(&args, None));
        assert_eq!(std::fs::read(&signature).unwrap(), expected);
        if index == 1 {
            let mut stdin_args = args.clone();
            stdin_args[6] = "-";
            stdin_args[12] = "-";
            assert_eq!(
                ok(run(
                    &stdin_args,
                    Some(b"HashSLH-DSA original message\0\xff")
                )),
                expected
            );
        }
        ok(run(
            &[
                "verify-hash-slh-dsa",
                "--digest",
                hash,
                "--object",
                &public,
                "--parameter-set",
                name,
                "--input",
                input.to_str().unwrap(),
                "--context-file",
                context.to_str().unwrap(),
                "--signature",
                signature.to_str().unwrap(),
            ],
            None,
        ));
        if index == 11 {
            ok(run(
                &[
                    "verify-hash-slh-dsa",
                    "--digest",
                    hash,
                    "--object",
                    &public,
                    "--parameter-set",
                    name,
                    "--input",
                    input.to_str().unwrap(),
                    "--context-file",
                    context.to_str().unwrap(),
                    "--signature",
                    "-",
                ],
                Some(&expected),
            ));
        }
        let digest = root.join(format!("hslh-{index}-0.digest"));
        let mut digest_args = args.clone();
        digest_args[6] = digest.to_str().unwrap();
        digest_args[12] = "-";
        digest_args.extend(["--input-kind", "digest"]);
        assert_eq!(ok(run(&digest_args, None)), expected);
        let mut bad = expected;
        bad[0] ^= 1;
        std::fs::write(&signature, &bad).unwrap();
        let result = run(
            &[
                "verify-hash-slh-dsa",
                "--digest",
                hash,
                "--object",
                &public,
                "--parameter-set",
                name,
                "--input",
                input.to_str().unwrap(),
                "--context-file",
                context.to_str().unwrap(),
                "--signature",
                signature.to_str().unwrap(),
            ],
            None,
        );
        assert_eq!(result.status.code(), Some(4));
        assert!(result.stdout.is_empty());
    }
    let generation = [
        "generate-hash-slh-dsa",
        "--token",
        "pkcs11:token=kdf-test",
        "--parameter-set",
        "slh-dsa-shake-128f",
        "--id",
        "686173682d736c682d636c69",
        "--label",
        "HashSLH CLI pair",
        "--always-authenticate",
        "--confirm",
    ];
    ok(run(&generation, None));
    assert!(!run(&generation, None).status.success());
}
