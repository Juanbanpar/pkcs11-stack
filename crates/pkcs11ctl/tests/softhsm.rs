// SPDX-License-Identifier: MIT OR Apache-2.0
//! Executes the actual CLI, only against the runner's disposable SoftHSM store.
use serde_json::Value;
use std::{
    path::PathBuf,
    process::{Command, Output},
};
struct Fixture {
    module: String,
    root: PathBuf,
    pin: String,
    so: String,
}
impl Fixture {
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .args(["--module", &self.module, "--format", "json"])
            .args(args)
            .output()
            .unwrap()
    }
    fn ok(&self, args: &[&str]) -> Value {
        let out = self.run(args);
        assert!(out.status.success(), "CLI command failed: {}", out.status);
        assert!(out.stderr.is_empty());
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
            "CLI command failed: {}",
            out.status
        );
        assert!(out.stdout.is_empty());
        let value: Value = serde_json::from_slice(&out.stderr).unwrap();
        assert!(value["error"]["kind"].is_string());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("12345678"));
    }
    fn path(&self, name: &str) -> String {
        self.root.join(name).to_str().unwrap().into()
    }
}
fn external(program: &str, args: &[&str]) {
    let out = Command::new(program).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "external command failed: {}",
        out.status
    );
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn oaep_explicit_mgf_and_binary_label_interoperate_and_preserve_outputs() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    if std::env::var("PKCS11_TEST_REQUIRE_RSA_OAEP_SHA2").as_deref() != Ok("1") {
        return;
    }
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let f = Fixture {
        module: std::env::var("PKCS11_TEST_MODULE").unwrap(),
        pin: root.join("oaep-parameters.pin").to_str().unwrap().into(),
        so: String::new(),
        root,
    };
    std::fs::write(&f.pin, b"12345678\n").unwrap();
    let input = f.path("cli-oaep-parameters-message");
    let cipher = f.path("cli-oaep-parameters-cipher");
    let plain = f.path("cli-oaep-parameters-plain");
    std::fs::write(&input, b"explicit OAEP context").unwrap();
    let result = f.run(&[
        "encrypt-rsa-oaep",
        "--object",
        "pkcs11:token=client-test;id=%20;type=public",
        "--digest",
        "sha256",
        "--mgf-digest",
        "sha512",
        "--label-hex",
        "00ff0123",
        "--input",
        &input,
        "--output",
        &cipher,
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    external(
        "openssl",
        &[
            "pkeyutl",
            "-decrypt",
            "-inkey",
            &f.path("cipher.key"),
            "-in",
            &cipher,
            "-out",
            &plain,
            "-pkeyopt",
            "rsa_padding_mode:oaep",
            "-pkeyopt",
            "rsa_oaep_md:sha256",
            "-pkeyopt",
            "rsa_mgf1_md:sha512",
            "-pkeyopt",
            "rsa_oaep_label:00ff0123",
        ],
    );
    assert_eq!(
        std::fs::read(&plain).unwrap(),
        std::fs::read(&input).unwrap()
    );
    external(
        "openssl",
        &[
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-keyform",
            "DER",
            "-inkey",
            &f.path("cipher-public.der"),
            "-in",
            &input,
            "-out",
            &cipher,
            "-pkeyopt",
            "rsa_padding_mode:oaep",
            "-pkeyopt",
            "rsa_oaep_md:sha256",
            "-pkeyopt",
            "rsa_mgf1_md:sha512",
            "-pkeyopt",
            "rsa_oaep_label:00ff0123",
        ],
    );
    std::fs::remove_file(&plain).unwrap();
    let args = |label, mgf| {
        vec![
            "decrypt-rsa-oaep",
            "--object",
            "pkcs11:token=client-test;id=%21;type=private",
            "--digest",
            "sha256",
            "--mgf-digest",
            mgf,
            "--label-hex",
            label,
            "--input",
            &cipher,
            "--output",
            &plain,
            "--pin-file",
            &f.pin,
            "--context-pin-file",
            &f.pin,
        ]
    };
    for (label, mgf) in [("00ff0124", "sha512"), ("00ff0123", "sha384")] {
        f.fail(&args(label, mgf), 5);
        assert!(!std::path::Path::new(&plain).exists());
    }
    let args = args("00ff0123", "sha512");
    let result = f.run(&args);
    assert!(result.status.success());
    assert_eq!(
        std::fs::read(&plain).unwrap(),
        std::fs::read(&input).unwrap()
    );
    f.fail(&args, 6);
    assert_eq!(
        std::fs::read(&plain).unwrap(),
        std::fs::read(&input).unwrap()
    );
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn command_workflows() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var("PKCS11_CLIENT_TEST_DIR").unwrap());
    let f = Fixture {
        module: std::env::var("PKCS11_TEST_MODULE").unwrap(),
        pin: root.join("user.pin").to_str().unwrap().into(),
        so: root.join("so.pin").to_str().unwrap().into(),
        root,
    };
    std::fs::write(&f.pin, b"12345678\n").unwrap();
    std::fs::write(&f.so, b"87654321\r\n").unwrap();
    let info = f.ok(&["info", "--interface-version", "2.40"]);
    assert_eq!(info["interface"]["version"], "2.40");
    assert_eq!(info["interface"]["legacy"], true);
    assert!(f.ok(&["info"])["interface"]["version"].is_string());
    f.ok(&["slots"]);
    let generated = f.ok(&[
        "generate",
        "--token",
        "pkcs11:token=client-test",
        "--kind",
        "rsa",
        "--purpose",
        "encryption",
        "--bits",
        "2048",
        "--id",
        "D9E1",
        "--label",
        "cli-encryption-purpose",
        "--always-authenticate",
        "--pin-file",
        &f.pin,
        "--confirm",
    ]);
    assert_eq!(generated["key"]["purpose"], "encryption");
    let choices = f.ok(&["generation-options", "--token", "pkcs11:token=client-test"]);
    assert!(
        choices["rsa_encryption"]
            .as_array()
            .unwrap()
            .iter()
            .any(|bits| bits == 2048)
    );
    let private = "pkcs11:token=client-test;id=%D9%E1;type=private";
    let attrs = f.ok(&[
        "inspect",
        "--object",
        private,
        "--attributes",
        "sign,sensitive,extractable,always-authenticate",
        "--pin-file",
        &f.pin,
    ]);
    assert_eq!(attrs["sign"]["value"], false);
    assert_eq!(attrs["sensitive"]["value"], true);
    assert_eq!(attrs["extractable"]["value"], false);
    assert_eq!(attrs["always-authenticate"]["value"], true);
    if std::env::var("PKCS11_TEST_REQUIRE_RSA_OAEP_SHA2").as_deref() == Ok("1") {
        let message = f.path("generated-rsa-message");
        let ciphertext = f.path("generated-rsa-ciphertext");
        let recovered = f.path("generated-rsa-recovered");
        std::fs::write(&message, b"generated RSA encryption purpose").unwrap();
        let result = f.run(&[
            "encrypt-rsa-oaep",
            "--object",
            "pkcs11:token=client-test;id=%D9%E1;type=public",
            "--digest",
            "sha256",
            "--input",
            &message,
            "--output",
            &ciphertext,
        ]);
        assert!(result.status.success());
        let result = f.run(&[
            "decrypt-rsa-oaep",
            "--object",
            private,
            "--digest",
            "sha256",
            "--input",
            &ciphertext,
            "--output",
            &recovered,
            "--pin-file",
            &f.pin,
            "--context-pin-file",
            &f.pin,
        ]);
        assert!(result.status.success());
        assert_eq!(
            std::fs::read(message).unwrap(),
            std::fs::read(recovered).unwrap()
        );
    }

    if std::env::var("PKCS11_TEST_REQUIRE_RSA_OAEP_SHA2").as_deref() == Ok("1") {
        let message = f.path("oaep-message");
        std::fs::write(&message, b"OAEP context-authentication CLI regression").unwrap();
        let ciphertext = f.path("oaep-ciphertext");
        let output = f.run(&[
            "encrypt-rsa-oaep",
            "--object",
            "pkcs11:token=client-test;id=%20;type=public",
            "--digest",
            "sha256",
            "--input",
            &message,
            "--output",
            &ciphertext,
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let plain = f.path("oaep-independent-plain");
        external(
            "openssl",
            &[
                "pkeyutl",
                "-decrypt",
                "-inkey",
                &f.path("cipher.key"),
                "-in",
                &ciphertext,
                "-out",
                &plain,
                "-pkeyopt",
                "rsa_padding_mode:oaep",
                "-pkeyopt",
                "rsa_oaep_md:sha256",
                "-pkeyopt",
                "rsa_mgf1_md:sha256",
            ],
        );
        assert_eq!(
            std::fs::read(&message).unwrap(),
            std::fs::read(&plain).unwrap()
        );
        let independent = f.path("oaep-independent-cipher");
        external(
            "openssl",
            &[
                "pkeyutl",
                "-encrypt",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                &f.path("cipher-public.der"),
                "-in",
                &message,
                "-out",
                &independent,
                "-pkeyopt",
                "rsa_padding_mode:oaep",
                "-pkeyopt",
                "rsa_oaep_md:sha256",
                "-pkeyopt",
                "rsa_mgf1_md:sha256",
            ],
        );
        let recovered = f.path("oaep-context-plain");
        let output = f.run(&[
            "decrypt-rsa-oaep",
            "--object",
            "pkcs11:token=client-test;id=%21;type=private",
            "--digest",
            "sha256",
            "--input",
            &independent,
            "--output",
            &recovered,
            "--pin-file",
            &f.pin,
            "--context-pin-file",
            &f.pin,
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(&message).unwrap(),
            std::fs::read(&recovered).unwrap()
        );
        let missing = f.path("oaep-missing-context");
        f.fail(
            &[
                "decrypt-rsa-oaep",
                "--object",
                "pkcs11:token=client-test;id=%21;type=private",
                "--digest",
                "sha256",
                "--input",
                &independent,
                "--output",
                &missing,
                "--pin-file",
                &f.pin,
            ],
            4,
        );
        assert!(!PathBuf::from(missing).exists());
        let wrong_pin = f.path("oaep-wrong-context.pin");
        std::fs::write(&wrong_pin, b"wrong-context").unwrap();
        let failed = f.path("oaep-wrong-context");
        f.fail(
            &[
                "decrypt-rsa-oaep",
                "--object",
                "pkcs11:token=client-test;id=%21;type=private",
                "--digest",
                "sha256",
                "--input",
                &independent,
                "--output",
                &failed,
                "--pin-file",
                &f.pin,
                "--context-pin-file",
                &wrong_pin,
            ],
            5,
        );
        assert!(!PathBuf::from(failed).exists());
    }

    let tokens = f.ok(&["tokens"]);
    let uninitialized = tokens
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["initialized"] == false)
        .unwrap();
    let expected = uninitialized["uri"].as_str().unwrap();
    let slot = uninitialized["slot_id"].as_u64().unwrap().to_string();
    f.fail(
        &[
            "init-token",
            "--slot",
            &slot,
            "--expected-token",
            "pkcs11:token=unexpected;manufacturer=;model=;serial=",
            "--label",
            "must-not-erase",
            "--so-pin-file",
            &f.so,
            "--confirm",
        ],
        2,
    );
    assert!(
        f.ok(&["tokens"])
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["slot_id"] == uninitialized["slot_id"]
                && entry["uri"] == uninitialized["uri"])
    );
    f.ok(&[
        "init-token",
        "--slot",
        &slot,
        "--expected-token",
        expected,
        "--label",
        "cli-test",
        "--so-pin-file",
        &f.so,
        "--confirm",
    ]);
    let current = f.ok(&["tokens"]);
    let initialized = current
        .as_array()
        .unwrap()
        .iter()
        .find(|token| token["label"] == "cli-test")
        .unwrap();
    let initialized_slot = initialized["slot_id"].as_u64().unwrap().to_string();
    f.fail(
        &[
            "init-token",
            "--slot",
            &initialized_slot,
            "--expected-token",
            expected,
            "--label",
            "must-not-erase",
            "--so-pin-file",
            &f.so,
            "--confirm",
        ],
        2,
    );
    let token = "pkcs11:token=cli-test";
    f.ok(&[
        "init-pin",
        "--token",
        token,
        "--role",
        "so",
        "--pin-file",
        &f.so,
        "--new-pin-file",
        &f.pin,
        "--confirm",
    ]);
    let mechanisms = f.ok(&["mechanisms", "--token", token]);
    assert!(!mechanisms.as_array().unwrap().is_empty());
    assert_eq!(f.ok(&["objects", "--token", token]), serde_json::json!([]));
    f.fail(&["objects", "--token", "pkcs11:token=runtime-test"], 3);
    f.fail(&["objects", "--token", "pkcs11:token=missing"], 3);
    f.fail(&["objects", "--token", token, "--protected-path"], 4);
    let bad = f.path("bad.pin");
    std::fs::write(&bad, b"definitely-wrong").unwrap();
    f.fail(&["objects", "--token", token, "--pin-file", &bad], 5);
    let random_file = f.path("random.bin");
    let random_args = [
        "random",
        "--token",
        token,
        "--length",
        "1048576",
        "--output",
        &random_file,
        "--pin-file",
        &f.pin,
    ];
    let out = f.run(&random_args);
    assert!(
        out.status.success(),
        "external command failed: {}",
        out.status
    );
    assert!(out.stdout.is_empty());
    assert!(out.stderr.is_empty());
    assert_eq!(std::fs::metadata(&random_file).unwrap().len(), 1048576);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&random_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    f.fail(&random_args, 6);
    let out = f.run(&[
        "random", "--token", token, "--length", "64", "--output", "-",
    ]);
    assert!(
        out.status.success(),
        "external command failed: {}",
        out.status
    );
    assert_eq!(out.stdout.len(), 64);
    assert!(out.stderr.is_empty());
    let failed_random = f.path("failed-random");
    f.fail(
        &[
            "random",
            "--token",
            "pkcs11:token=missing",
            "--length",
            "32",
            "--output",
            &failed_random,
        ],
        3,
    );
    assert!(!std::path::Path::new(&failed_random).exists());
    for (kind, id) in [
        ("rsa", "01"),
        ("p256", "02"),
        ("p384", "03"),
        ("p521", "04"),
    ] {
        f.ok(&[
            "generate",
            "--token",
            token,
            "--kind",
            kind,
            "--id",
            id,
            "--label",
            kind,
            "--pin-file",
            &f.pin,
            "--confirm",
        ]);
        let reference = format!("pkcs11:token=cli-test;object={kind};type=private");
        let attrs = f.ok(&[
            "inspect",
            "--object",
            &reference,
            "--attributes",
            "sensitive,extractable,sign",
            "--pin-file",
            &f.pin,
        ]);
        assert_eq!(attrs["sensitive"]["value"], true);
        assert_eq!(attrs["extractable"]["value"], false);
        assert_eq!(attrs["sign"]["value"], true);
        f.ok(&["capabilities", "--key", &reference, "--pin-file", &f.pin]);
        let public = format!("pkcs11:token=cli-test;object={kind};type=public");
        let exported = f.path(&format!("{kind}-public.der"));
        let out = f.run(&["export", "--object", &public, "--output", &exported]);
        assert!(out.status.success());
        assert!(out.stdout.is_empty());
        external(
            "openssl",
            &[
                "pkey", "-pubin", "-inform", "DER", "-in", &exported, "-noout",
            ],
        );
    }
    let objects = f.ok(&["objects", "--token", token, "--pin-file", &f.pin]);
    assert_eq!(objects.as_array().unwrap().len(), 8);
    for row in objects.as_array().unwrap() {
        f.ok(&[
            "inspect",
            "--object",
            row["uri"].as_str().unwrap(),
            "--pin-file",
            &f.pin,
        ]);
    }
    let diag = f.ok(&[
        "diagnose",
        "--token",
        token,
        "--pin-file",
        &f.pin,
        "--pool-size",
        "3",
    ]);
    assert_eq!(diag["capacity"], 3);
    assert_eq!(diag["exhaustion_verified"], true);
    assert_eq!(diag["reuse_verified"], true);
    let data = f.path("data.bin");
    std::fs::write(&data, b"\0public data\xff").unwrap();
    f.ok(&[
        "import",
        "--token",
        token,
        "--kind",
        "data",
        "--id",
        "20",
        "--label",
        "data",
        "--input",
        &data,
        "--pin-file",
        &f.pin,
        "--confirm",
    ]);
    let data_uri = "pkcs11:token=cli-test;object=data;type=data";
    let out = f.run(&["export", "--object", data_uri, "--output", "-"]);
    assert!(out.status.success());
    assert_eq!(out.stdout, b"\0public data\xff");
    assert!(out.stderr.is_empty());
    f.ok(&[
        "set-label",
        "--object",
        data_uri,
        "--label",
        "renamed",
        "--pin-file",
        &f.pin,
        "--confirm",
    ]);
    f.fail(&["inspect", "--object", data_uri], 3);
    f.ok(&[
        "delete",
        "--object",
        "pkcs11:token=cli-test;object=renamed;type=data",
        "--pin-file",
        &f.pin,
        "--confirm",
    ]);
    let ed = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pkcs11-client/tests/fixtures/ed25519.der");
    f.ok(&[
        "import",
        "--token",
        token,
        "--kind",
        "cert",
        "--id",
        "21",
        "--label",
        "ed25519",
        "--input",
        ed.to_str().unwrap(),
        "--pin-file",
        &f.pin,
        "--confirm",
    ]);
    let ed_uri = "pkcs11:token=cli-test;object=ed25519;type=cert";
    let exported = f.path("exported.der");
    let out = f.run(&["export", "--object", ed_uri, "--output", &exported]);
    assert!(
        out.status.success(),
        "external command failed: {}",
        out.status
    );
    assert!(out.stdout.is_empty());
    assert_eq!(
        std::fs::read(&exported).unwrap(),
        std::fs::read(ed).unwrap()
    );
    let metadata = f.ok(&[
        "inspect",
        "--object",
        ed_uri,
        "--attributes",
        "subject,issuer,serial",
    ]);
    for name in ["subject", "issuer", "serial"] {
        assert_eq!(metadata[name]["status"], "available");
        assert!(!metadata[name]["value"]["hex"].as_str().unwrap().is_empty());
    }
    f.fail(&["certificate", "--object", ed_uri], 4);
    f.fail(
        &[
            "export",
            "--object",
            "pkcs11:token=cli-test;object=rsa;type=private",
            "--pin-file",
            &f.pin,
            "--output",
            &f.path("forbidden"),
        ],
        2,
    );
    assert!(!f.root.join("forbidden").exists());
    // Use the RSA fixture that remains after the key-replacement test.
    let key = "pkcs11:token=client-test;object=wrong;type=private";
    let cert = "pkcs11:token=client-test;object=wrong;type=cert";
    f.ok(&["certificate", "--object", cert]);
    f.ok(&[
        "bind",
        "--key",
        key,
        "--certificate",
        cert,
        "--pin-file",
        &f.pin,
    ]);
    f.fail(
        &[
            "bind",
            "--key",
            key,
            "--certificate",
            "pkcs11:token=client-test;object=rsa;type=cert",
            "--pin-file",
            &f.pin,
        ],
        4,
    );
    f.fail(
        &[
            "capabilities",
            "--key",
            "pkcs11:token=client-test;object=duplicate;type=private",
            "--pin-file",
            &f.pin,
        ],
        3,
    );
    let message = f.path("cli-message");
    std::fs::write(&message, b"CLI signing message\n").unwrap();
    let signature = f.path("cli-signature");
    let plan = f.ok(&[
        "plan",
        "--key",
        key,
        "--algorithm",
        "rsa-pkcs1",
        "--digest",
        "sha256",
        "--hashing",
        "software",
        "--input",
        &message,
        "--pin-file",
        &f.pin,
    ]);
    assert_eq!(plan["hash_location"], "Software");
    let args = [
        "sign",
        "--key",
        key,
        "--certificate",
        cert,
        "--algorithm",
        "rsa-pkcs1",
        "--digest",
        "sha256",
        "--input",
        &message,
        "--output",
        &signature,
        "--pin-file",
        &f.pin,
    ];
    let out = f.run(&args);
    assert!(
        out.status.success(),
        "external command failed: {}",
        out.status
    );
    assert!(out.stdout.is_empty());
    external(
        "openssl",
        &[
            "dgst",
            "-sha256",
            "-verify",
            &f.path("05-public.pem"),
            "-signature",
            &signature,
            &message,
        ],
    );
    f.fail(&args, 6); // existing output is never overwritten
    let verified = f.ok(&[
        "verify",
        "--certificate",
        cert,
        "--algorithm",
        "rsa-pkcs1",
        "--digest",
        "sha256",
        "--input",
        &message,
        "--signature",
        &signature,
    ]);
    assert_eq!(verified["verified"], true);
    assert_eq!(verified["trust_validated"], false);
    let public_key = key.replace("type=private", "type=public");
    let native_args = [
        "verify-token",
        "--key",
        &public_key,
        "--algorithm",
        "rsa-pkcs1",
        "--digest",
        "sha256",
        "--input",
        &message,
        "--signature",
        &signature,
    ];
    assert_eq!(f.ok(&native_args)["verification"], "token");
    let altered = f.path("altered-message");
    std::fs::write(&altered, b"changed message").unwrap();
    f.fail(
        &[
            "verify",
            "--certificate",
            cert,
            "--algorithm",
            "rsa-pkcs1",
            "--digest",
            "sha256",
            "--input",
            &altered,
            "--signature",
            &signature,
        ],
        4,
    );
    f.fail(
        &[
            "verify-token",
            "--key",
            &public_key,
            "--algorithm",
            "rsa-pkcs1",
            "--digest",
            "sha256",
            "--input",
            &altered,
            "--signature",
            &signature,
        ],
        4,
    );
    let prehash = f.path("sha256");
    external(
        "openssl",
        &["dgst", "-sha256", "-binary", "-out", &prehash, &message],
    );
    let pss = f.path("pss-signature");
    let out = f.run(&[
        "sign",
        "--key",
        key,
        "--algorithm",
        "rsa-pss",
        "--digest",
        "sha256",
        "--mgf-digest",
        "sha256",
        "--salt-length",
        "20",
        "--input-kind",
        "digest",
        "--input",
        &prehash,
        "--output",
        &pss,
        "--pin-file",
        &f.pin,
    ]);
    assert!(
        out.status.success(),
        "external command failed: {}",
        out.status
    );
    external(
        "openssl",
        &[
            "dgst",
            "-sha256",
            "-verify",
            &f.path("05-public.pem"),
            "-signature",
            &pss,
            "-sigopt",
            "rsa_padding_mode:pss",
            "-sigopt",
            "rsa_pss_saltlen:20",
            "-sigopt",
            "rsa_mgf1_md:sha256",
            &message,
        ],
    );
    f.ok(&[
        "verify",
        "--certificate",
        cert,
        "--algorithm",
        "rsa-pss",
        "--digest",
        "sha256",
        "--mgf-digest",
        "sha256",
        "--salt-length",
        "20",
        "--input-kind",
        "digest",
        "--input",
        &prehash,
        "--signature",
        &pss,
    ]);
    f.fail(
        &[
            "sign",
            "--key",
            key,
            "--certificate",
            cert,
            "--algorithm",
            "rsa-pss",
            "--digest",
            "sha256",
            "--mgf-digest",
            "sha384",
            "--salt-length",
            "20",
            "--input",
            &message,
            "--output",
            &f.path("unsupported"),
            "--pin-file",
            &f.pin,
        ],
        4,
    );
    let ec_key = "pkcs11:token=client-test;object=p521;type=private";
    let ec_cert = "pkcs11:token=client-test;object=p521;type=cert";
    let out = f.run(&[
        "sign",
        "--key",
        ec_key,
        "--certificate",
        ec_cert,
        "--algorithm",
        "ecdsa",
        "--digest",
        "sha256",
        "--hashing",
        "software",
        "--input",
        &message,
        "--output",
        "-",
        "--pin-file",
        &f.pin,
    ]);
    assert!(
        out.status.success(),
        "external command failed: {}",
        out.status
    );
    assert_eq!(out.stdout.len(), 132);
    let always = "pkcs11:token=client-test;object=always;type=private";
    f.fail(
        &[
            "sign",
            "--key",
            always,
            "--algorithm",
            "rsa-pkcs1",
            "--digest",
            "sha256",
            "--input",
            &message,
            "--output",
            &f.path("context-missing"),
            "--pin-file",
            &f.pin,
        ],
        4,
    );
    let out = f.run(&[
        "sign",
        "--key",
        always,
        "--algorithm",
        "rsa-pkcs1",
        "--digest",
        "sha256",
        "--input",
        &message,
        "--output",
        "-",
        "--pin-file",
        &f.pin,
        "--context-pin-file",
        &f.pin,
    ]);
    assert!(
        out.status.success(),
        "external command failed: {}",
        out.status
    );
    assert_eq!(out.stdout.len(), 256);
    // USER and SO changes each execute exactly once; subsequent login verifies state.
    let new = f.path("new.pin");
    std::fs::write(&new, b"11223344").unwrap();
    f.ok(&[
        "set-pin",
        "--token",
        token,
        "--pin-file",
        &f.pin,
        "--new-pin-file",
        &new,
        "--confirm",
    ]);
    f.fail(&["objects", "--token", token, "--pin-file", &f.pin], 5);
    f.ok(&["objects", "--token", token, "--pin-file", &new]);
    f.ok(&[
        "set-pin",
        "--token",
        token,
        "--pin-file",
        &new,
        "--new-pin-file",
        &f.pin,
        "--confirm",
    ]);
    f.ok(&[
        "set-pin",
        "--token",
        token,
        "--role",
        "so",
        "--pin-file",
        &f.so,
        "--new-pin-file",
        &new,
        "--confirm",
    ]);
    f.ok(&[
        "set-pin",
        "--token",
        token,
        "--role",
        "so",
        "--pin-file",
        &new,
        "--new-pin-file",
        &f.so,
        "--confirm",
    ]);
    listed_empty_selectors_are_preserved(&f);
    // The same guard supports erasure of an initialized token when its current
    // metadata was explicitly selected, not just first-time initialization.
    let inventory = f.ok(&["tokens"]);
    let current = inventory
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["label"] == "cli-test")
        .unwrap();
    let slot = current["slot_id"].as_u64().unwrap().to_string();
    f.ok(&[
        "init-token",
        "--slot",
        &slot,
        "--expected-token",
        current["uri"].as_str().unwrap(),
        "--label",
        "cli-erased",
        "--so-pin-file",
        &f.so,
        "--confirm",
    ]);
    assert_eq!(
        f.ok(&["objects", "--token", "pkcs11:token=cli-erased"]),
        serde_json::json!([])
    );
}

fn listed_empty_selectors_are_preserved(f: &Fixture) {
    use pkcs11_client::{Authentication, CertificateDocument, Pin, Provider, SessionMode};
    let der = include_bytes!("../../pkcs11-client/tests/fixtures/rsa.der").to_vec();
    let provider = Provider::load(&f.module).unwrap();
    let pin = secrecy::SecretString::from("12345678");
    let mut session = provider
        .management(
            &"pkcs11:token=cli-test".parse().unwrap(),
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    let document = CertificateDocument::from_der(der.clone()).unwrap();
    session.import_certificate(&document, b"", b"").unwrap();
    session
        .import_certificate(&document, b"other", b"review-other")
        .unwrap();
    session.close().unwrap();
    provider.finalize().unwrap();
    let rows = f.ok(&["objects", "--token", "pkcs11:token=cli-test"]);
    let row = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["attributes"]["class"]["value"] == "cert"
                && r["attributes"]["label"]["value"]["hex"] == ""
        })
        .unwrap();
    let uri = row["uri"].as_str().unwrap();
    let parsed: pkcs11_locator::Pkcs11Uri = uri.parse().unwrap();
    assert_eq!(parsed.path_attribute("object"), Some(b"".as_slice()));
    assert_eq!(parsed.path_attribute("id"), Some(b"".as_slice()));
    let output = f.run(&["export", "--object", uri, "--output", "-"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, der);
    f.ok(&["delete", "--object", uri, "--pin-file", &f.pin, "--confirm"]);
    f.ok(&[
        "certificate",
        "--object",
        "pkcs11:token=cli-test;object=review-other;type=cert",
    ]);
}

#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn typed_generation_permissions_and_public_export() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let f = Fixture {
        module: std::env::var("PKCS11_TEST_MODULE").unwrap(),
        pin: root.join("generation-user.pin").to_str().unwrap().into(),
        so: String::new(),
        root,
    };
    std::fs::write(&f.pin, b"12345678\n").unwrap();
    let token = "pkcs11:token=client-test";
    let options = f.ok(&["generation-options", "--token", token]);
    assert_eq!(options["advisory"], true);
    assert_eq!(
        options["ecdh"],
        serde_json::json!(["ecdh-p256", "ecdh-p384", "ecdh-p521"])
    );
    assert_eq!(
        options["aes"],
        serde_json::json!(["aes128", "aes192", "aes256"])
    );
    for (index, kind) in ["ecdh-p256", "ecdh-p384", "ecdh-p521"]
        .into_iter()
        .enumerate()
    {
        let id = format!("a8{index:02x}");
        let args = [
            "generate",
            "--token",
            token,
            "--kind",
            kind,
            "--id",
            &id,
            "--label",
            "CLI ECDH",
            "--pin-file",
            &f.pin,
            "--confirm",
        ];
        let generated = f.ok(&args);
        assert_eq!(generated["key"]["algorithm"], "ec");
        assert_eq!(generated["key"]["purpose"], "derivation");
        f.fail(&args, 2);
        let private = format!("{token};id=%A8%{index:02X};type=private");
        let attrs = f.ok(&[
            "inspect",
            "--object",
            &private,
            "--attributes",
            "sign,sensitive,extractable",
            "--pin-file",
            &f.pin,
        ]);
        assert_eq!(attrs["sign"]["value"], false);
        assert_eq!(attrs["sensitive"]["value"], true);
        assert_eq!(attrs["extractable"]["value"], false);
        let public = format!("{token};id=%A8%{index:02X};type=public");
        let path = f.path(&format!("{kind}.der"));
        let exported = f.run(&["export", "--object", &public, "--output", &path]);
        assert!(exported.status.success());
        assert!(exported.stdout.is_empty());
        pkcs11_client::EcdhPeer::from_spki_der(&std::fs::read(path).unwrap()).unwrap();
    }
    for (index, kind) in ["aes128", "aes192", "aes256"].into_iter().enumerate() {
        for (purpose_index, purpose) in ["encryption", "wrapping"].into_iter().enumerate() {
            let id = format!("a9{index:02x}{purpose_index:02x}");
            let args = [
                "generate",
                "--token",
                token,
                "--kind",
                kind,
                "--purpose",
                purpose,
                "--id",
                &id,
                "--label",
                "CLI AES",
                "--pin-file",
                &f.pin,
                "--confirm",
            ];
            let generated = f.ok(&args);
            assert_eq!(generated["key"]["algorithm"], "aes");
            assert_eq!(generated["key"]["purpose"], purpose);
            assert_eq!(generated["extractable"], false);
            f.fail(&args, 2);
            let secret = format!("{token};id=%A9%{index:02X}%{purpose_index:02X};type=secret-key");
            let attrs = f.ok(&[
                "inspect",
                "--object",
                &secret,
                "--attributes",
                "sensitive,extractable",
                "--pin-file",
                &f.pin,
            ]);
            assert_eq!(attrs["sensitive"]["value"], true);
            assert_eq!(attrs["extractable"]["value"], false);
            let forbidden = f.path(&format!("forbidden-{id}"));
            f.fail(
                &[
                    "export",
                    "--object",
                    &secret,
                    "--output",
                    &forbidden,
                    "--pin-file",
                    &f.pin,
                ],
                2,
            );
            assert!(!std::path::Path::new(&forbidden).exists());
        }
    }
}

#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn token_digests_stream_files_and_stdin() {
    use std::io::Write;
    use std::process::Stdio;
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let f = Fixture {
        module: std::env::var("PKCS11_TEST_MODULE").unwrap(),
        root,
        pin: String::new(),
        so: String::new(),
    };
    let input = f.path("digest-cli-input");
    std::fs::write(&input, b"abc").unwrap();
    let options = f.ok(&["digest-algorithms", "--token", "pkcs11:token=client-test"]);
    assert_eq!(options["advisory"], true);
    for algorithm in options["algorithms"].as_array().unwrap() {
        let algorithm = algorithm.as_str().unwrap();
        let result = f.ok(&[
            "digest",
            "--token",
            "pkcs11:token=client-test",
            "--algorithm",
            algorithm,
            "--input",
            &input,
        ]);
        let expected = Command::new("openssl")
            .args(["dgst", &format!("-{algorithm}"), "-binary", &input])
            .output()
            .unwrap();
        assert!(expected.status.success());
        let expected: String = expected.stdout.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(result["digest_hex"], expected);
    }
    f.fail(
        &[
            "digest",
            "--token",
            "pkcs11:token=client-test",
            "--algorithm",
            "sha256",
            "--input",
            f.root.to_str().unwrap(),
        ],
        6,
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .args([
            "--module",
            &f.module,
            "--format",
            "json",
            "digest",
            "--token",
            "pkcs11:token=client-test",
            "--algorithm",
            "sha256",
            "--input",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"abc").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["result"]["digest_hex"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn public_key_import_verifies_signatures_and_enforces_purpose() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let f = Fixture {
        module: std::env::var("PKCS11_TEST_MODULE").unwrap(),
        pin: root.join("public-import.pin").to_str().unwrap().into(),
        so: String::new(),
        root,
    };
    std::fs::write(&f.pin, b"12345678\n").unwrap();
    let binary = |args: &[&str]| {
        let output = f.run(args);
        assert!(
            output.status.success(),
            "binary command failed: {}",
            output.status
        );
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    };
    let message = f.path("public-import-message");
    std::fs::write(&message, b"CLI public key import").unwrap();
    // The earlier client replacement test changes the RSA key at ID 01.
    for (source, algorithm) in [
        ("05", "rsa-pkcs1"),
        ("02", "ecdsa"),
        ("03", "ecdsa"),
        ("04", "ecdsa"),
    ] {
        let id = format!("FA10{source}");
        let uri = format!("pkcs11:token=client-test;id=%FA%10%{source};type=public");
        let input = f.path(&format!("{source}-public.der"));
        let args = [
            "import",
            "--token",
            "pkcs11:token=client-test",
            "--kind",
            "public-key",
            "--purpose",
            "verification",
            "--input",
            &input,
            "--id",
            &id,
            "--label",
            "CLI verification key",
            "--pin-file",
            &f.pin,
            "--confirm",
        ];
        let imported = f.ok(&args);
        assert_eq!(imported["purpose"], "verification");
        f.fail(&args, 2);
        let signature = f.path(&format!("public-import-{source}.sig"));
        let private = format!("pkcs11:token=client-test;id=%{source};type=private");
        binary(&[
            "sign",
            "--key",
            &private,
            "--algorithm",
            algorithm,
            "--digest",
            "sha256",
            "--hashing",
            "software",
            "--input",
            &message,
            "--output",
            &signature,
            "--pin-file",
            &f.pin,
        ]);
        f.ok(&[
            "verify-token",
            "--key",
            &uri,
            "--algorithm",
            algorithm,
            "--digest",
            "sha256",
            "--hashing",
            "software",
            "--input",
            &message,
            "--signature",
            &signature,
        ]);
        let exported = f.path(&format!("public-import-{source}.der"));
        binary(&["export", "--object", &uri, "--output", &exported]);
        assert_eq!(
            std::fs::read(&exported).unwrap(),
            std::fs::read(&input).unwrap()
        );
    }
    let input = f.path("cipher-public.der");
    f.ok(&[
        "import",
        "--token",
        "pkcs11:token=client-test",
        "--kind",
        "public-key",
        "--purpose",
        "encryption",
        "--input",
        &input,
        "--id",
        "FA20",
        "--label",
        "CLI encryption key",
        "--pin-file",
        &f.pin,
        "--confirm",
    ]);
    if std::env::var("PKCS11_TEST_REQUIRE_RSA_OAEP_SHA2").as_deref() == Ok("1") {
        let ciphertext = f.path("public-import.cipher");
        let recovered = f.path("public-import.plain");
        binary(&[
            "encrypt-rsa-oaep",
            "--object",
            "pkcs11:token=client-test;id=%FA%20;type=public",
            "--digest",
            "sha256",
            "--input",
            &message,
            "--output",
            &ciphertext,
        ]);
        binary(&[
            "decrypt-rsa-oaep",
            "--object",
            "pkcs11:token=client-test;id=%20;type=private",
            "--digest",
            "sha256",
            "--input",
            &ciphertext,
            "--output",
            &recovered,
            "--pin-file",
            &f.pin,
        ]);
        assert_eq!(
            std::fs::read(&recovered).unwrap(),
            std::fs::read(&message).unwrap()
        );
    }
}
