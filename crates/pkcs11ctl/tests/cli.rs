// SPDX-License-Identifier: MIT OR Apache-2.0
//! Executable contracts that require no PKCS#11 library.
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "pkcs11ctl-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn help_and_version_need_no_module() {
    for name in [
        "info",
        "slots",
        "tokens",
        "objects",
        "mechanisms",
        "inspect",
        "export",
        "certificate",
        "capabilities",
        "plan",
        "bind",
        "sign",
        "verify",
        "random",
        "kem-capabilities",
        "encapsulate",
        "decapsulate",
        "hkdf-capabilities",
        "derive-hkdf",
        "derive-hybrid",
        "diagnose",
        "init-token",
        "init-pin",
        "set-pin",
        "generate",
        "generation-options",
        "aes-gcm-capabilities",
        "encrypt-aes-gcm",
        "decrypt-aes-gcm",
        "import",
        "set-label",
        "delete",
    ] {
        let out = run(&[name, "--help"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stderr.is_empty());
    }
    assert!(run(&["--version"]).status.success());
}

#[test]
fn verifies_independent_fixtures_without_loading_a_module() {
    use der::{Decode, Sequence, asn1::UintRef};
    #[derive(Sequence)]
    struct EcdsaSignature<'a> {
        r: UintRef<'a>,
        s: UintRef<'a>,
    }
    let dir = Scratch::new();
    let fixtures =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkcs11-client/tests/fixtures");
    let message = fixtures.join("message.txt");
    for kind in ["rsa", "rsa-pss", "p256", "p384", "p521"] {
        let (algorithm, certificate) = match kind {
            "rsa" => ("rsa-pkcs1", "rsa"),
            "rsa-pss" => ("rsa-pss", "rsa"),
            _ => ("ecdsa", kind),
        };
        let certificate = fixtures.join(format!("{certificate}.der"));
        for digest in ["sha256", "sha384", "sha512"] {
            let mut signature = fixtures.join(format!("{kind}-{digest}.sig"));
            if algorithm == "ecdsa" {
                let encoded = std::fs::read(&signature).unwrap();
                let decoded = EcdsaSignature::from_der(&encoded).unwrap();
                let width = match kind {
                    "p256" => 32,
                    "p384" => 48,
                    _ => 66,
                };
                let mut raw = vec![0; width * 2];
                for (value, component) in [decoded.r, decoded.s].iter().zip(raw.chunks_mut(width)) {
                    let bytes = value.as_bytes();
                    component[width - bytes.len()..].copy_from_slice(bytes);
                }
                signature = dir.0.join(format!("{kind}-{digest}.raw"));
                std::fs::write(&signature, raw).unwrap();
            }
            let mut args = vec![
                "--module",
                "/must-not-load",
                "--format",
                "json",
                "verify",
                "--certificate-file",
                certificate.to_str().unwrap(),
                "--signature",
                signature.to_str().unwrap(),
                "--algorithm",
                algorithm,
                "--digest",
                digest,
                "--input",
                message.to_str().unwrap(),
            ];
            if kind == "rsa-pss" {
                args.extend(["--mgf-digest", digest, "--salt-length", "20"]);
            }
            let result = run(&args);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(result.stderr.is_empty());
            let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(
                value,
                serde_json::json!({"schema_version":1,"command":"verify",
                "result":{"verified":true,"trust_validated":false}})
            );
        }
    }
}

#[test]
fn verification_rejects_mismatch_bad_parameters_and_oversized_inputs() {
    let dir = Scratch::new();
    let fixtures =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkcs11-client/tests/fixtures");
    let certificate = fixtures.join("rsa.der");
    let signature = fixtures.join("rsa-sha256.sig");
    let input = dir.0.join("message");
    std::fs::write(&input, b"do-not-echo-message").unwrap();
    let args = [
        "--format",
        "json",
        "verify",
        "--certificate-file",
        certificate.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--algorithm",
        "rsa-pkcs1",
        "--digest",
        "sha256",
        "--input",
        input.to_str().unwrap(),
    ];
    let result = run(&args);
    assert_eq!(result.status.code(), Some(4));
    assert!(result.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("do-not-echo-message"));
    let value: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(value["error"]["message"], "signature verification failed");
    std::fs::write(&input, std::fs::read(fixtures.join("message.txt")).unwrap()).unwrap();
    for (option, path) in [
        ("--certificate-file", fixtures.join("p256.der")),
        ("--certificate-file", input.clone()),
        ("--signature", input.clone()),
    ] {
        let mut all = args.to_vec();
        let index = all.iter().position(|&arg| arg == option).unwrap() + 1;
        all[index] = path.to_str().unwrap();
        let result = run(&all);
        assert_eq!(result.status.code(), Some(4));
        assert!(result.stdout.is_empty());
    }
    for extra in [
        vec!["--input-kind", "digest"],
        vec!["--mgf-digest", "sha256"],
        vec!["--pin-file", "/must-not-read"],
        vec!["--certificate", "pkcs11:token=t;object=c;type=cert"],
        vec!["--hashing", "software"],
    ] {
        let mut all = args.to_vec();
        all.extend(extra);
        assert_eq!(run(&all).status.code(), Some(2));
    }
    for (option, maximum) in [
        ("--signature", 16 * 1024),
        ("--certificate-file", 1024 * 1024),
        ("--input", 64 * 1024 * 1024),
    ] {
        let file = std::fs::File::create(&input).unwrap();
        file.set_len(maximum + 1).unwrap();
        let mut all = args.to_vec();
        let index = all.iter().position(|&arg| arg == option).unwrap() + 1;
        all[index] = input.to_str().unwrap();
        assert_eq!(run(&all).status.code(), Some(2));
        std::fs::write(&input, b"message").unwrap();
    }
}

#[test]
fn verification_accepts_stdin_and_rejects_multiple_stdin_inputs() {
    use std::{io::Write, process::Stdio};
    let fixtures =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkcs11-client/tests/fixtures");
    let certificate = fixtures.join("rsa.der");
    let signature = fixtures.join("rsa-sha256.sig");
    let base = [
        "verify",
        "--certificate-file",
        certificate.to_str().unwrap(),
        "--algorithm",
        "rsa-pkcs1",
        "--digest",
        "sha256",
    ];
    for (input, sig, bytes) in [
        (
            "-",
            signature.to_str().unwrap(),
            std::fs::read(fixtures.join("message.txt")).unwrap(),
        ),
        (
            fixtures.join("message.txt").to_str().unwrap(),
            "-",
            std::fs::read(&signature).unwrap(),
        ),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args(base)
            .args(["--input", input, "--signature", sig])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let mut args = base.to_vec();
    args.extend(["--input", "-", "--signature", "-"]);
    assert_eq!(run(&args).status.code(), Some(2));
}

#[test]
fn random_validates_length_before_output_and_preserves_existing_files() {
    let dir = Scratch::new();
    let output = dir.0.join("random");
    let args = [
        "--module",
        "/missing",
        "--format",
        "json",
        "random",
        "--token",
        "pkcs11:token=t",
        "--output",
        output.to_str().unwrap(),
        "--length",
    ];
    for length in [
        "0",
        "1048577",
        "-1",
        "not-a-number",
        "184467440737095516160",
    ] {
        let mut all = args.to_vec();
        all.push(length);
        let result = run(&all);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(!output.exists());
    }
    for length in ["1", "1048576"] {
        let mut all = args.to_vec();
        all.push(length);
        assert_eq!(run(&all).status.code(), Some(5));
        assert!(!output.exists());
        std::fs::write(&output, b"preserve").unwrap();
        assert_eq!(run(&all).status.code(), Some(6));
        assert_eq!(std::fs::read(&output).unwrap(), b"preserve");
        std::fs::remove_file(&output).unwrap();
    }
}

#[test]
fn provider_commands_require_a_module_before_reading_files() {
    for arguments in [
        vec![
            "verify",
            "--certificate",
            "pkcs11:token=t;object=c;type=cert",
            "--algorithm",
            "rsa-pkcs1",
            "--digest",
            "sha256",
            "--input",
            "/must-not-read",
            "--signature",
            "/must-not-read",
        ],
        vec![
            "random",
            "--token",
            "pkcs11:token=t",
            "--length",
            "32",
            "--output",
            "-",
            "--pin-file",
            "/must-not-read",
        ],
    ] {
        assert_eq!(run(&arguments).status.code(), Some(2));
    }
}
#[test]
fn rejects_arguments_without_echoing_secrets() {
    let marker = "do-not-echo-this-secret";
    for args in [
        vec![
            "--format", "json", "inspect", "--object", marker, "--bad", marker,
        ],
        vec![
            "--format",
            "json",
            "--module",
            "/missing",
            "inspect",
            "--object",
            "pkcs11:token=x;object=y?pin-value=do-not-echo-this-secret",
        ],
        vec![
            "--format",
            "json",
            "--module",
            "/missing",
            "delete",
            "--object",
            "pkcs11:token=x;object=y",
        ],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        let text = String::from_utf8(out.stderr).unwrap();
        assert!(!text.contains(marker));
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["error"]["kind"], "input");
    }
}
#[test]
fn validates_parameters_before_loading_module() {
    let dir = Scratch::new();
    let file = dir.0.join("input");
    std::fs::write(&file, b"message").unwrap();
    let args = [
        "--module",
        "/missing",
        "plan",
        "--key",
        "pkcs11:token=x;object=k;type=private",
        "--algorithm",
        "rsa-pss",
        "--digest",
        "sha256",
        "--input",
        file.to_str().unwrap(),
    ];
    let out = run(&args);
    assert_eq!(out.status.code(), Some(2));
    let out = run(&[
        "--module",
        "/missing",
        "diagnose",
        "--token",
        "pkcs11:token=x;object=ignored",
        "--pool-size",
        "0",
    ]);
    assert_eq!(out.status.code(), Some(2));
    let out = run(&[
        "--module",
        "/missing",
        "generate",
        "--token",
        "pkcs11:token=x",
        "--kind",
        "p256",
        "--bits",
        "2048",
        "--id",
        "01",
        "--label",
        "key",
        "--confirm",
    ]);
    assert_eq!(out.status.code(), Some(2));
}
#[test]
fn existing_output_is_preserved_and_failed_output_removed() {
    let dir = Scratch::new();
    let input = dir.0.join("input");
    let output = dir.0.join("output");
    std::fs::write(&input, b"message").unwrap();
    std::fs::write(&output, b"preserve").unwrap();
    let args = [
        "--module",
        "/missing",
        "sign",
        "--key",
        "pkcs11:token=x;object=k;type=private",
        "--algorithm",
        "rsa-pkcs1",
        "--digest",
        "sha256",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ];
    assert_eq!(run(&args).status.code(), Some(6));
    assert_eq!(std::fs::read(&output).unwrap(), b"preserve");
    std::fs::remove_file(&output).unwrap();
    assert_eq!(run(&args).status.code(), Some(5));
    assert!(!output.exists());
}

#[test]
fn malformed_prehash_is_rejected_before_loading_or_creating_output() {
    let dir = Scratch::new();
    let input = dir.0.join("digest");
    let output = dir.0.join("signature");
    std::fs::write(&input, [0; 31]).unwrap();
    let result = run(&[
        "--module",
        "/missing",
        "--format",
        "json",
        "sign",
        "--key",
        "pkcs11:token=test;object=key;type=private",
        "--algorithm",
        "rsa-pkcs1",
        "--digest",
        "sha256",
        "--input-kind",
        "digest",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(
        result.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.exists());
    assert!(result.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "input");
}

#[test]
fn typed_selectors_are_rejected_before_loading_module() {
    for args in [
        vec![
            "capabilities",
            "--key",
            "pkcs11:token=test;object=key;type=cert",
        ],
        vec!["capabilities", "--key", "pkcs11:token=test;object=key"],
        vec![
            "certificate",
            "--object",
            "pkcs11:token=test;object=cert;type=private",
        ],
        vec![
            "bind",
            "--key",
            "pkcs11:token=test;object=key;type=private",
            "--certificate",
            "pkcs11:token=test;object=cert;type=public",
        ],
    ] {
        let mut all = vec!["--module", "/missing", "--format", "json"];
        all.extend(args);
        let result = run(&all);
        assert_eq!(
            result.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
        assert_eq!(error["error"]["kind"], "input");
    }
}

#[test]
fn token_erasure_requires_complete_expected_identity_before_loading() {
    let dir = Scratch::new();
    let pin = dir.0.join("so.pin");
    std::fs::write(&pin, b"public-fixture-pin").unwrap();
    let base = [
        "--module",
        "/missing",
        "--format",
        "json",
        "init-token",
        "--slot",
        "0",
        "--label",
        "new-label",
        "--so-pin-file",
        pin.to_str().unwrap(),
        "--confirm",
    ];
    let result = run(&base);
    assert_eq!(result.status.code(), Some(2));
    for uri in [
        "pkcs11:",
        "pkcs11:token=only-label",
        "pkcs11:token=t;manufacturer=m;model=x",
        "pkcs11:token=t;manufacturer=m;model=x;serial=s;slot-id=0",
        "pkcs11:token=t;manufacturer=m;model=x;serial=s;object=k",
        "pkcs11:token=t;manufacturer=m;model=x;serial=s?pin-value=redaction-canary",
    ] {
        let mut args = base.to_vec();
        args.extend(["--expected-token", uri]);
        let result = run(&args);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("redaction-canary"));
    }
    for uri in [
        "pkcs11:token=;manufacturer=;model=;serial=",
        "pkcs11:token=t;manufacturer=m;model=x;serial=s",
    ] {
        let mut args = base.to_vec();
        args.extend(["--expected-token", uri]);
        // A complete expectation passes validation and reaches module loading.
        assert_eq!(run(&args).status.code(), Some(5));
    }
}

#[test]
fn ml_dsa_offline_verification_checks_all_parameters_and_contexts() {
    let dir = Scratch::new();
    let fixtures =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkcs11-client/tests/fixtures");
    let context = dir.0.join("context");
    std::fs::write(&context, b"fixture-context").unwrap();
    for parameter in ["44", "65", "87"] {
        let algorithm = format!("ml-dsa-{parameter}");
        let cert = fixtures.join(format!("mldsa{parameter}.der"));
        let message = fixtures.join("message.txt");
        for suffix in ["sig", "context.sig"] {
            let sig = fixtures.join(format!("mldsa{parameter}.{suffix}"));
            let mut args = vec![
                "--module",
                "/must-not-load",
                "--format",
                "json",
                "verify",
                "--algorithm",
                &algorithm,
                "--certificate-file",
                cert.to_str().unwrap(),
                "--input",
                message.to_str().unwrap(),
                "--signature",
                sig.to_str().unwrap(),
            ];
            if suffix == "context.sig" {
                args.extend(["--context-file", context.to_str().unwrap()]);
            }
            let result = run(&args);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(
                value["result"],
                serde_json::json!({"verified":true,"trust_validated":false})
            );
            for bad in [
                vec!["--digest", "sha256"],
                vec!["--input-kind", "digest"],
                vec!["--mgf-digest", "sha256"],
                vec!["--salt-length", "0"],
            ] {
                let mut invalid = args.clone();
                invalid.extend(bad);
                assert_eq!(run(&invalid).status.code(), Some(2));
            }
            if suffix == "context.sig" {
                args.truncate(args.len() - 2);
                assert_eq!(run(&args).status.code(), Some(4));
            }
            let wrong = if parameter == "44" {
                "ml-dsa-65"
            } else {
                "ml-dsa-44"
            };
            let mut invalid = args.clone();
            invalid[6] = wrong;
            assert_eq!(run(&invalid).status.code(), Some(4));
        }
    }
}

#[test]
fn ml_dsa_options_fail_before_provider_and_output_creation() {
    let dir = Scratch::new();
    let message = dir.0.join("message");
    let context = dir.0.join("context");
    let output = dir.0.join("signature");
    std::fs::write(&message, b"message").unwrap();
    std::fs::write(&context, [0; 256]).unwrap();
    let base = [
        "--module",
        "/must-not-load",
        "--format",
        "json",
        "sign",
        "--key",
        "pkcs11:token=test;id=%01;type=private",
        "--algorithm",
        "ml-dsa-44",
        "--input",
        message.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ];
    for extra in [
        vec!["--hashing", "token"],
        vec!["--digest", "sha256"],
        vec!["--input-kind", "digest"],
        vec!["--context-file", "-"],
        vec!["--context-file", context.to_str().unwrap()],
    ] {
        let mut args = base.to_vec();
        args.extend(extra);
        let result = run(&args);
        assert_eq!(
            result.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stdout.is_empty());
        assert!(!output.exists());
    }
    for extra in [
        vec!["--context-file", context.to_str().unwrap()],
        vec!["--hedging", "required"],
    ] {
        let mut args = base.to_vec();
        args[8] = "ecdsa";
        args.extend(["--digest", "sha256"]);
        args.extend(extra);
        assert_eq!(run(&args).status.code(), Some(2));
    }
    for kind in ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"] {
        assert_eq!(
            run(&[
                "--module",
                "/must-not-load",
                "generate",
                "--token",
                "pkcs11:token=test",
                "--kind",
                kind,
                "--id",
                "01",
                "--label",
                "test",
                "--bits",
                "2048",
                "--confirm"
            ])
            .status
            .code(),
            Some(2)
        );
    }
    assert_eq!(
        run(&[
            "--module",
            "/must-not-load",
            "bind",
            "--key-family",
            "ml-dsa",
            "--key",
            "pkcs11:token=test;id=%01;type=private",
            "--certificate",
            "pkcs11:token=test;id=%02;type=cert",
            "--hashing",
            "token"
        ])
        .status
        .code(),
        Some(2)
    );
    assert!(!output.exists());
}

#[test]
fn key_establishment_rejects_invalid_options_before_loading() {
    let dir = Scratch::new();
    let public = "pkcs11:token=test;id=%01;type=public";
    let private = "pkcs11:token=test;id=%01;type=private";
    let base = "pkcs11:token=test;id=%02;type=secret-key";
    let output = dir.0.join("ciphertext");
    let output = output.to_str().unwrap();
    for kind in ["ml-kem-512", "ml-kem-768", "ml-kem-1024"] {
        for extra in [vec!["--bits", "2048"], vec!["--always-authenticate"]] {
            let mut args = vec![
                "--module",
                "/must-not-load",
                "--format",
                "json",
                "generate",
                "--token",
                "pkcs11:token=test",
                "--kind",
                kind,
                "--id",
                "01",
                "--label",
                "recipient",
                "--confirm",
            ];
            args.extend(extra);
            let result = run(&args);
            assert_eq!(result.status.code(), Some(2));
            assert!(result.stdout.is_empty());
        }
    }
    let cases = [
        vec![
            "encapsulate",
            "--object",
            public,
            "--parameter-set",
            "ml-kem-512",
            "--id",
            "02",
            "--label",
            "sender",
            "--output",
            output,
        ],
        vec![
            "encapsulate",
            "--object",
            private,
            "--parameter-set",
            "ml-kem-512",
            "--id",
            "02",
            "--label",
            "sender",
            "--output",
            output,
            "--confirm",
        ],
        vec![
            "derive-hkdf",
            "--object",
            public,
            "--digest",
            "sha256",
            "--kind",
            "aes256",
            "--id",
            "03",
            "--label",
            "derived",
            "--confirm",
        ],
        vec![
            "derive-hkdf",
            "--object",
            base,
            "--digest",
            "sha256",
            "--kind",
            "aes256",
            "--length",
            "32",
            "--id",
            "03",
            "--label",
            "derived",
            "--confirm",
        ],
        vec![
            "derive-hkdf",
            "--object",
            base,
            "--digest",
            "sha256",
            "--kind",
            "derivation-secret",
            "--length",
            "0",
            "--id",
            "03",
            "--label",
            "derived",
            "--confirm",
        ],
        vec![
            "derive-hkdf",
            "--object",
            base,
            "--digest",
            "sha256",
            "--kind",
            "derivation-secret",
            "--length",
            "8161",
            "--id",
            "03",
            "--label",
            "derived",
            "--confirm",
        ],
        vec![
            "derive-hkdf",
            "--object",
            base,
            "--digest",
            "sha256",
            "--kind",
            "derivation-secret",
            "--id",
            "03",
            "--label",
            "derived",
            "--confirm",
        ],
        vec![
            "derive-hkdf",
            "--object",
            base,
            "--digest",
            "sha256",
            "--kind",
            "aes256",
            "--salt-file",
            "-",
            "--id",
            "03",
            "--label",
            "derived",
            "--confirm",
        ],
        vec![
            "export",
            "--key-family",
            "ml-kem",
            "--object",
            private,
            "--output",
            output,
        ],
        vec![
            "kem-capabilities",
            "--object",
            private,
            "--operation",
            "encapsulate",
        ],
        vec![
            "hkdf-capabilities",
            "--object",
            public,
            "--digest",
            "sha256",
        ],
        vec![
            "encapsulate",
            "--object",
            public,
            "--parameter-set",
            "ml-kem-512",
            "--id",
            "02",
            "--label",
            "sender",
            "--output",
            output,
            "--role",
            "so",
            "--confirm",
        ],
    ];
    for args in cases {
        let mut invocation = vec!["--module", "/must-not-load", "--format", "json"];
        invocation.extend(args);
        let result = run(&invocation);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(!std::path::Path::new(output).exists());
    }
}
#[test]
fn key_establishment_bounds_files_and_preserves_outputs() {
    let dir = Scratch::new();
    let input = dir.0.join("input");
    let input = input.to_str().unwrap();
    let output = dir.0.join("ciphertext");
    let output = output.to_str().unwrap();
    for length in [0, 1, 767, 769] {
        std::fs::write(input, vec![0; length]).unwrap();
        let result = run(&[
            "--module",
            "/must-not-load",
            "decapsulate",
            "--object",
            "pkcs11:token=test;id=%01;type=private",
            "--parameter-set",
            "ml-kem-512",
            "--input",
            input,
            "--id",
            "02",
            "--label",
            "receiver",
            "--confirm",
        ]);
        assert_eq!(result.status.code(), Some(2));
    }
    std::fs::write(input, vec![0; 4097]).unwrap();
    for flag in ["--salt-file", "--info-file"] {
        assert_eq!(
            run(&[
                "--module",
                "/must-not-load",
                "derive-hkdf",
                "--object",
                "pkcs11:token=test;id=%02;type=secret-key",
                "--digest",
                "sha256",
                "--kind",
                "aes256",
                flag,
                input,
                "--id",
                "03",
                "--label",
                "derived",
                "--confirm"
            ])
            .status
            .code(),
            Some(2)
        );
    }
    std::fs::write(input, b"invalid SPKI").unwrap();
    assert_eq!(
        run(&[
            "--module",
            "/must-not-load",
            "import",
            "--token",
            "pkcs11:token=test",
            "--kind",
            "ml-kem",
            "--input",
            input,
            "--id",
            "01",
            "--label",
            "peer",
            "--confirm"
        ])
        .status
        .code(),
        Some(4)
    );
    let args = [
        "--module",
        "/must-not-load",
        "encapsulate",
        "--object",
        "pkcs11:token=test;id=%01;type=public",
        "--parameter-set",
        "ml-kem-512",
        "--id",
        "02",
        "--label",
        "sender",
        "--output",
        output,
        "--confirm",
    ];
    assert_eq!(run(&args).status.code(), Some(5));
    assert!(!std::path::Path::new(output).exists());
    std::fs::write(output, b"existing output").unwrap();
    assert_eq!(run(&args).status.code(), Some(6));
    assert_eq!(std::fs::read(output).unwrap(), b"existing output");
}

#[test]
fn hybrid_validation_precedes_module_loading() {
    let dir = Scratch::new();
    let info = dir.0.join("info");
    let salt = dir.0.join("salt");
    std::fs::write(&info, b"protocol v1").unwrap();
    std::fs::write(&salt, [0; 129]).unwrap();
    for extra in [
        vec![],
        vec!["--digest", "sha256", "--info-file", info.to_str().unwrap()],
        vec![
            "--digest",
            "sha512",
            "--info-file",
            info.to_str().unwrap(),
            "--salt-file",
            salt.to_str().unwrap(),
        ],
    ] {
        let mut args = vec![
            "--module",
            "/must-not-load",
            "--format",
            "json",
            "derive-hybrid",
            "--object",
            "pkcs11:token=test;id=%01;type=secret-key",
            "--post-quantum",
            "pkcs11:token=test;id=%02;type=secret-key",
            "--kind",
            "aes256",
            "--id",
            "03",
            "--label",
            "hybrid",
            "--confirm",
        ];
        args.extend(extra);
        let result = run(&args);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
        assert_eq!(error["error"]["kind"], "input");
    }
}

#[test]
fn typed_generation_rejects_invalid_options_before_loading_a_provider() {
    let long = "x".repeat(129);
    let long_id = "AA".repeat(129);
    for (kind, id, label, extra) in [
        ("ecdh-p256", "01", "key", vec!["--always-authenticate"]),
        ("ecdh-p384", "01", "key", vec!["--bits", "2048"]),
        ("ecdh-p521", "01", "key", vec!["--purpose", "wrapping"]),
        ("ecdh-p256", "01", long.as_str(), vec![]),
        ("ecdh-p256", long_id.as_str(), "key", vec![]),
        ("aes128", "01", "key", vec![]),
        (
            "aes192",
            "01",
            "key",
            vec!["--purpose", "wrapping", "--always-authenticate"],
        ),
        (
            "aes256",
            "01",
            "key",
            vec!["--purpose", "encryption", "--bits", "256"],
        ),
        ("aes256", "01", long.as_str(), vec!["--purpose", "wrapping"]),
        ("p256", "01", "key", vec!["--purpose", "encryption"]),
    ] {
        let mut args = vec![
            "--module",
            "/missing",
            "--format",
            "json",
            "generate",
            "--token",
            "pkcs11:token=x",
            "--kind",
            kind,
            "--id",
            id,
            "--label",
            label,
            "--confirm",
        ];
        args.extend(extra);
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{kind}");
        assert!(out.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
        assert_eq!(error["error"]["kind"], "input");
    }
}

#[test]
fn aes_gcm_preflight_rejects_invalid_parameters_before_provider_or_output() {
    let dir = Scratch::new();
    let input = dir.0.join("input");
    std::fs::write(&input, [0; 15]).unwrap();
    let output = dir.0.join("output");
    for (command, nonce, object, extra) in [
        (
            "encrypt-aes-gcm",
            "00",
            "pkcs11:token=x;object=k;type=secret-key",
            vec![],
        ),
        (
            "encrypt-aes-gcm",
            "zzzzzzzzzzzzzzzzzzzzzzzz",
            "pkcs11:token=x;object=k;type=secret-key",
            vec![],
        ),
        (
            "encrypt-aes-gcm",
            "000000000000000000000000",
            "pkcs11:token=x;object=k;type=private",
            vec![],
        ),
        (
            "encrypt-aes-gcm",
            "000000000000000000000000",
            "pkcs11:token=x;object=k;type=secret-key",
            vec!["--aad-file", "-"],
        ),
        (
            "decrypt-aes-gcm",
            "000000000000000000000000",
            "pkcs11:token=x;object=k;type=secret-key",
            vec![],
        ),
    ] {
        let mut args = vec![
            "--module",
            "/missing",
            "--format",
            "json",
            command,
            "--object",
            object,
            "--nonce",
            nonce,
            "--input",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ];
        args.extend(extra);
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(!output.exists());
    }
    let oversized = dir.0.join("oversized");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len(pkcs11_client::AES_GCM_MAXIMUM_PLAINTEXT as u64 + 1)
        .unwrap();
    let out = run(&[
        "--module",
        "/missing",
        "encrypt-aes-gcm",
        "--object",
        "pkcs11:token=x;object=k;type=secret-key",
        "--nonce",
        "000000000000000000000000",
        "--input",
        oversized.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!output.exists());
}
