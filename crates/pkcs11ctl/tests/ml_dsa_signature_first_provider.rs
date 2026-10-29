// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit signature-first CLI verification with an implementing provider.
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
fn ok(output: Output) -> Output {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
#[test]
#[ignore = "requires disposable Kryoptic runner with ML-DSA enabled"]
fn ml_dsa_cli_signature_first_files_stdin_contexts_and_mismatches() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = std::env::var("PKCS11_TEST_KDF_MODULE").unwrap();
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap())
        .join("cli-mldsa-signature-first");
    std::fs::create_dir(&root).unwrap();
    let pin = root.join("pin");
    std::fs::write(&pin, b"12345678").unwrap();
    let context = root.join("context");
    let message = root.join("message");
    let tag = root.join("signature");
    let spki = root.join("public.der");
    let run = |args: &[&str], stdin: Option<&[u8]>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command
            .args(["--module", &module, "--format", "json"])
            .args(args)
            .args(["--pin-file", pin.to_str().unwrap()]);
        command
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        if let Some(bytes) = stdin {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        }
        child.wait_with_output().unwrap()
    };
    for (index, algorithm) in ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]
        .into_iter()
        .enumerate()
    {
        let id = format!("d9{index:02x}");
        let key = format!("pkcs11:token=kdf-test;id=%D9%{index:02X};type=private");
        let public = key.replace("private", "public");
        let mut generate = vec![
            "generate",
            "--token",
            "pkcs11:token=kdf-test",
            "--kind",
            algorithm,
            "--id",
            &id,
            "--label",
            "CLI ML-DSA signature-first",
            "--confirm",
        ];
        if index == 1 {
            generate.push("--always-authenticate");
        }
        ok(run(&generate, None));
        ok(run(
            &[
                "export",
                "--object",
                &public,
                "--key-family",
                "ml-dsa",
                "--output",
                spki.to_str().unwrap(),
            ],
            None,
        ));
        let verifier =
            pkcs11_client::MlDsaVerifyingKey::from_spki_der(&std::fs::read(&spki).unwrap())
                .unwrap();
        std::fs::remove_file(&spki).unwrap();
        for domain in [vec![], vec![0xA5; 255]] {
            std::fs::write(&context, &domain).unwrap();
            for length in [0, 1, 256 * 1024] {
                let bytes = vec![0x42; length];
                std::fs::write(&message, &bytes).unwrap();
                let mut sign = vec![
                    "sign",
                    "--key",
                    &key,
                    "--algorithm",
                    algorithm,
                    "--context-file",
                    context.to_str().unwrap(),
                    "--input",
                    message.to_str().unwrap(),
                    "--output",
                    "-",
                    "--multipart",
                ];
                if index == 1 {
                    sign.extend(["--context-pin-file", pin.to_str().unwrap()]);
                }
                let signature = ok(run(&sign, None)).stdout;
                std::fs::write(&tag, &signature).unwrap();
                verifier
                    .verify_reader(
                        pkcs11_client::MlDsaParameters {
                            parameter_set: verifier.parameter_set(),
                            context: &domain,
                            hedging: pkcs11_client::MlDsaHedging::Required,
                        },
                        &mut &bytes[..],
                        &signature,
                    )
                    .unwrap();
                let mut verify = vec![
                    "verify-token",
                    "--key",
                    &public,
                    "--algorithm",
                    algorithm,
                    "--context-file",
                    context.to_str().unwrap(),
                    "--input",
                    message.to_str().unwrap(),
                    "--signature",
                    tag.to_str().unwrap(),
                    "--multipart",
                ];
                ok(run(&verify, None));
                if length == 256 * 1024 {
                    let position = verify.iter().position(|a| *a == "--input").unwrap() + 1;
                    verify[position] = "-";
                    ok(run(&verify, Some(&bytes)));
                    verify[position] = message.to_str().unwrap();
                    let position = verify.iter().position(|a| *a == "--signature").unwrap() + 1;
                    verify[position] = "-";
                    ok(run(&verify, Some(&signature)));
                    verify[position] = tag.to_str().unwrap();
                }
                let mut wrong = signature;
                wrong[0] ^= 1;
                std::fs::write(&tag, wrong).unwrap();
                let result = run(&verify, None);
                assert_eq!(result.status.code(), Some(4));
                assert!(result.stdout.is_empty());
            }
        }
    }
}
