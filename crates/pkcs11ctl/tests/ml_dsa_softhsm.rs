// SPDX-License-Identifier: MIT OR Apache-2.0
//! ML-DSA CLI workflows against the runner's disposable PQC provider.
use serde_json::Value;
use std::{
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture {
    module: String,
    root: PathBuf,
}
impl Fixture {
    fn path(&self, name: &str) -> String {
        self.root.join(name).to_str().unwrap().into()
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args(["--module", &self.module, "--format", "json"])
            .args(args)
            .output()
            .unwrap()
    }
    fn ok(&self, args: &[&str]) -> Value {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stderr.is_empty());
        if out.stdout.is_empty() {
            return Value::Null;
        }
        let value: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["command"], args[0]);
        value["result"].clone()
    }
    fn fail(&self, args: &[&str], code: i32) {
        let out = self.run(args);
        assert_eq!(
            out.status.code(),
            Some(code),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty());
        let value: Value = serde_json::from_slice(&out.stderr).unwrap();
        assert!(value["error"]["kind"].is_string());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("12345678"));
    }
}
fn openssl(args: &[&str]) {
    let out = Command::new(std::env::var_os("PKCS11_TEST_PQC_OPENSSL").unwrap())
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore = "requires PKCS11_TEST_REQUIRE_PQC=1 tools/test-softhsm.sh"]
fn ml_dsa_cli_generation_signing_binding_and_verification() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    assert_eq!(std::env::var("PKCS11_TEST_REQUIRE_PQC").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap()).join("cli-pqc");
    std::fs::create_dir(&root).unwrap();
    let f = Fixture {
        module: std::env::var("PKCS11_TEST_MODULE").unwrap(),
        root,
    };
    let pin = f.path("user.pin");
    let input = f.path("message");
    let context = f.path("context");
    let issuer_key = f.path("issuer.key");
    let issuer_cert = f.path("issuer.pem");
    std::fs::write(&pin, b"12345678\n").unwrap();
    std::fs::write(&input, b"CLI ML-DSA message\n").unwrap();
    std::fs::write(&context, b"cli-context").unwrap();
    openssl(&["genpkey", "-algorithm", "ED25519", "-out", &issuer_key]);
    openssl(&[
        "x509",
        "-new",
        "-key",
        &issuer_key,
        "-subj",
        "/CN=CLI-Test-CA",
        "-days",
        "1",
        "-out",
        &issuer_cert,
    ]);
    for (index, (algorithm, size)) in [
        ("ml-dsa-44", 2420),
        ("ml-dsa-65", 3309),
        ("ml-dsa-87", 4627),
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("d1{index:02x}");
        let cert_id = format!("d2{index:02x}");
        let key = format!("pkcs11:token=pqc-test;id=%D1%{index:02X};type=private");
        let public = key.replace("private", "public");
        let cert = format!("pkcs11:token=pqc-test;id=%D2%{index:02X};type=cert");
        let mut generate = vec![
            "generate",
            "--token",
            "pkcs11:token=pqc-test",
            "--kind",
            algorithm,
            "--label",
            "CLI ML-DSA",
            "--id",
            &id,
            "--pin-file",
            &pin,
            "--confirm",
        ];
        if index == 1 {
            generate.push("--always-authenticate");
        }
        let generated = f.ok(&generate);
        assert_eq!(generated["key"]["parameter_set"], algorithm);
        assert_eq!(generated["extractable"], false);
        let caps = f.ok(&[
            "capabilities",
            "--key-family",
            "ml-dsa",
            "--key",
            &key,
            "--pin-file",
            &pin,
        ]);
        assert_eq!(caps["key"], generated["key"]);
        assert_eq!(caps["can_sign"], true);
        assert_eq!(caps["always_authenticate"], index == 1);
        let spki = f.path(&format!("{index}.spki.der"));
        let pem = f.path(&format!("{index}.pem"));
        let certificate = f.path(&format!("{index}.cert.der"));
        f.ok(&[
            "export",
            "--key-family",
            "ml-dsa",
            "--object",
            &public,
            "--output",
            &spki,
        ]);
        openssl(&[
            "pkey", "-pubin", "-inform", "DER", "-in", &spki, "-out", &pem,
        ]);
        openssl(&[
            "x509",
            "-new",
            "-force_pubkey",
            &pem,
            "-CA",
            &issuer_cert,
            "-CAkey",
            &issuer_key,
            "-set_serial",
            &(index + 1).to_string(),
            "-subj",
            "/CN=CLI-ML-DSA",
            "-days",
            "1",
            "-outform",
            "DER",
            "-out",
            &certificate,
        ]);
        f.ok(&[
            "import",
            "--token",
            "pkcs11:token=pqc-test",
            "--kind",
            "cert",
            "--id",
            &cert_id,
            "--label",
            "CLI certificate",
            "--input",
            &certificate,
            "--pin-file",
            &pin,
            "--confirm",
        ]);
        let info = f.ok(&["certificate", "--key-family", "ml-dsa", "--object", &cert]);
        assert_eq!(info["key"], generated["key"]);
        assert_eq!(info["trust_validated"], false);
        let plan = f.ok(&[
            "plan",
            "--key",
            &key,
            "--algorithm",
            algorithm,
            "--input",
            &input,
            "--context-file",
            &context,
            "--pin-file",
            &pin,
        ]);
        assert_eq!(plan["hedging"], "required");
        assert_eq!(plan["context_length"], 11);
        let mut bind = vec![
            "bind",
            "--key-family",
            "ml-dsa",
            "--key",
            &key,
            "--certificate",
            &cert,
            "--pin-file",
            &pin,
        ];
        if index == 1 {
            bind.extend(["--context-pin-file", &pin]);
        }
        assert_eq!(f.ok(&bind)["bound"], true);
        for bound in [false, true] {
            let sig = f.path(&format!("{index}-{bound}.sig"));
            let mut sign = vec![
                "sign",
                "--key",
                &key,
                "--algorithm",
                algorithm,
                "--input",
                &input,
                "--context-file",
                &context,
                "--pin-file",
                &pin,
                "--output",
                &sig,
            ];
            if index == 1 {
                sign.extend(["--context-pin-file", &pin]);
            }
            if bound {
                sign.extend(["--certificate", &cert]);
            }
            f.ok(&sign);
            assert_eq!(std::fs::metadata(&sig).unwrap().len(), size);
            openssl(&[
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                &spki,
                "-keyform",
                "DER",
                "-in",
                &input,
                "-sigfile",
                &sig,
                "-pkeyopt",
                "context-string:cli-context",
            ]);
            for selector in [
                ["--certificate", cert.as_str()],
                ["--certificate-file", certificate.as_str()],
            ] {
                let mut verify = vec![
                    "verify",
                    selector[0],
                    selector[1],
                    "--algorithm",
                    algorithm,
                    "--input",
                    &input,
                    "--signature",
                    &sig,
                    "--context-file",
                    &context,
                ];
                assert_eq!(f.ok(&verify)["verified"], true);
                verify.truncate(verify.len() - 2);
                f.fail(&verify, 4);
            }
            f.fail(&sign, 6);
            assert_eq!(std::fs::metadata(&sig).unwrap().len(), size);
        }
        let failed = f.path(&format!("{index}.failed"));
        if index == 1 {
            f.fail(
                &[
                    "sign",
                    "--key",
                    &key,
                    "--algorithm",
                    algorithm,
                    "--input",
                    &input,
                    "--output",
                    &failed,
                    "--pin-file",
                    &pin,
                ],
                4,
            );
            assert!(!PathBuf::from(&failed).exists());
        }
        let wrong = if index == 0 { "ml-dsa-65" } else { "ml-dsa-44" };
        f.fail(
            &[
                "sign",
                "--key",
                &key,
                "--algorithm",
                wrong,
                "--input",
                &input,
                "--output",
                &failed,
                "--pin-file",
                &pin,
            ],
            4,
        );
        assert!(!PathBuf::from(&failed).exists());
        // A certificate with the same parameter set but a different public key must fail binding.
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pkcs11-client/tests/fixtures")
            .join(format!("mldsa{}.der", [44, 65, 87][index]));
        let wrong_id = format!("d3{index:02x}");
        let wrong_cert = format!("pkcs11:token=pqc-test;id=%D3%{index:02X};type=cert");
        f.ok(&[
            "import",
            "--token",
            "pkcs11:token=pqc-test",
            "--kind",
            "cert",
            "--id",
            &wrong_id,
            "--label",
            "wrong certificate",
            "--input",
            fixture.to_str().unwrap(),
            "--pin-file",
            &pin,
            "--confirm",
        ]);
        let mut sign = vec![
            "sign",
            "--key",
            &key,
            "--certificate",
            &wrong_cert,
            "--algorithm",
            algorithm,
            "--input",
            &input,
            "--output",
            &failed,
            "--pin-file",
            &pin,
        ];
        if index == 1 {
            sign.extend(["--context-pin-file", &pin]);
        }
        f.fail(&sign, 4);
        assert!(!PathBuf::from(&failed).exists());
        if index == 0 {
            let empty = f.path("empty");
            let binary_context = f.path("binary-context");
            std::fs::write(&empty, b"").unwrap();
            std::fs::write(&binary_context, [0xA5; 255]).unwrap();
            let mut deterministic = vec![];
            for (attempt, hedging) in ["preferred", "deterministic", "deterministic"]
                .into_iter()
                .enumerate()
            {
                let sig = f.path(&format!("edge-{attempt}.sig"));
                f.ok(&[
                    "sign",
                    "--key",
                    &key,
                    "--algorithm",
                    algorithm,
                    "--input",
                    &empty,
                    "--context-file",
                    &binary_context,
                    "--hedging",
                    hedging,
                    "--pin-file",
                    &pin,
                    "--output",
                    &sig,
                ]);
                assert_eq!(
                    f.ok(&[
                        "verify",
                        "--certificate-file",
                        &certificate,
                        "--algorithm",
                        algorithm,
                        "--input",
                        &empty,
                        "--signature",
                        &sig,
                        "--context-file",
                        &binary_context
                    ])["verified"],
                    true
                );
                if hedging == "deterministic" {
                    deterministic.push(std::fs::read(sig).unwrap());
                }
            }
            assert_eq!(deterministic[0], deterministic[1]);
        }
    }
    std::fs::remove_file(issuer_key).unwrap();
}
