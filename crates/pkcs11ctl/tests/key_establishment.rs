// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI key establishment using the runner's disposable Kryoptic store.
use serde_json::Value;
use std::{
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture {
    module: String,
    root: PathBuf,
    pin: String,
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
        let output = self.run(args);
        assert!(
            output.status.success(),
            "CLI command failed: {}",
            output.status
        );
        assert!(output.stderr.is_empty());
        if output.stdout.is_empty() {
            return Value::Null;
        }
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["schema_version"], 1);
        value["result"].clone()
    }
    fn fail(&self, args: &[&str], code: i32) {
        let output = self.run(args);
        assert_eq!(output.status.code(), Some(code));
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(error["error"]["kind"].is_string());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("12345678"));
    }
}
fn object(id: &str, kind: &str) -> String {
    format!("pkcs11:token=kdf-test;id=%D0%{id};type={kind}")
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn cli_ml_kem_public_exchange_hkdf_and_output_contracts() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let pin = root.join("user.pin").to_str().unwrap().to_owned();
    std::fs::write(&pin, b"12345678\n").unwrap();
    let f = Fixture {
        module: std::env::var("PKCS11_TEST_KDF_MODULE").unwrap(),
        root,
        pin,
    };
    let salt = f.path("salt");
    let info = f.path("info");
    std::fs::write(&salt, b"public test salt").unwrap();
    std::fs::write(&info, b"CLI protocol v1").unwrap();
    for (index, (parameter, length)) in [
        ("ml-kem-512", 768),
        ("ml-kem-768", 1088),
        ("ml-kem-1024", 1568),
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("d0{index:02x}");
        let uri_id = format!("{index:02X}");
        let public = object(&uri_id, "public");
        let private = object(&uri_id, "private");
        let generated = f.ok(&[
            "generate",
            "--token",
            "pkcs11:token=kdf-test",
            "--kind",
            parameter,
            "--id",
            &id,
            "--label",
            "CLI recipient",
            "--pin-file",
            &f.pin,
            "--confirm",
        ]);
        assert_eq!(generated["key"]["parameter_set"], parameter);
        let caps = f.ok(&[
            "kem-capabilities",
            "--object",
            &private,
            "--operation",
            "decapsulate",
            "--pin-file",
            &f.pin,
        ]);
        assert_eq!(caps["ciphertext_length"], length);
        let spki = f.path(&format!("{index}.spki.der"));
        f.ok(&[
            "export",
            "--object",
            &public,
            "--key-family",
            "ml-kem",
            "--output",
            &spki,
        ]);
        let imported_id = format!("d1{index:02x}");
        let imported = format!("pkcs11:token=kdf-test;id=%D1%{index:02X};type=public");
        f.ok(&[
            "import",
            "--token",
            "pkcs11:token=kdf-test",
            "--kind",
            "ml-kem",
            "--input",
            &spki,
            "--id",
            &imported_id,
            "--label",
            "CLI peer",
            "--pin-file",
            &f.pin,
            "--confirm",
        ]);
        let sender_id = format!("d2{index:02x}00");
        let receiver_id = format!("d2{index:02x}01");
        let ciphertext = f.path(&format!("{index}.ciphertext"));
        let enc = [
            "encapsulate",
            "--object",
            &imported,
            "--parameter-set",
            parameter,
            "--id",
            &sender_id,
            "--label",
            "CLI sender",
            "--output",
            &ciphertext,
            "--pin-file",
            &f.pin,
            "--confirm",
        ];
        f.ok(&enc);
        assert_eq!(std::fs::metadata(&ciphertext).unwrap().len(), length);
        f.fail(&enc, 6);
        assert_eq!(std::fs::metadata(&ciphertext).unwrap().len(), length);
        let failed = f.path(&format!("{index}.failed"));
        let mut duplicate = enc.to_vec();
        duplicate[10] = &failed;
        f.fail(&duplicate, 2);
        assert!(!PathBuf::from(&failed).exists());
        let dec = [
            "decapsulate",
            "--object",
            &private,
            "--parameter-set",
            parameter,
            "--input",
            &ciphertext,
            "--id",
            &receiver_id,
            "--label",
            "CLI receiver",
            "--pin-file",
            &f.pin,
            "--confirm",
        ];
        assert_eq!(f.ok(&dec)["decapsulated"], true);
        f.fail(&dec, 2);
        for direction in 0..=1 {
            let base =
                format!("pkcs11:token=kdf-test;id=%D2%{index:02X}%{direction:02X};type=secret-key");
            assert_eq!(
                f.ok(&[
                    "hkdf-capabilities",
                    "--object",
                    &base,
                    "--digest",
                    "sha256",
                    "--pin-file",
                    &f.pin
                ])["input_length"],
                32
            );
            f.fail(
                &[
                    "hkdf-capabilities",
                    "--object",
                    &base,
                    "--digest",
                    "sha384",
                    "--pin-file",
                    &f.pin,
                ],
                4,
            );
            let id = format!("d3{index:02x}{direction:02x}");
            let args = [
                "derive-hkdf",
                "--object",
                &base,
                "--digest",
                "sha256",
                "--kind",
                "aes256",
                "--salt-file",
                &salt,
                "--info-file",
                &info,
                "--id",
                &id,
                "--label",
                "CLI AES key",
                "--pin-file",
                &f.pin,
                "--confirm",
            ];
            assert_eq!(f.ok(&args)["derived"], true);
            f.fail(&args, 2);
            let derived =
                format!("pkcs11:token=kdf-test;id=%D3%{index:02X}%{direction:02X};type=secret-key");
            let denied = f.path(&format!("{index}-{direction}.secret"));
            f.fail(
                &[
                    "export",
                    "--object",
                    &derived,
                    "--output",
                    &denied,
                    "--pin-file",
                    &f.pin,
                ],
                2,
            );
            assert!(!PathBuf::from(&denied).exists());
            // Retain derived keys for the runner's independent agreement check.
            f.ok(&[
                "delete",
                "--object",
                &base,
                "--pin-file",
                &f.pin,
                "--confirm",
            ]);
        }
        for target in [&imported, &private, &public] {
            f.ok(&[
                "delete",
                "--object",
                target,
                "--pin-file",
                &f.pin,
                "--confirm",
            ]);
        }
    }
}

#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn cli_hybrid_combines_token_components() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let pin = root.join("hybrid.pin").to_str().unwrap().to_owned();
    std::fs::write(&pin, b"12345678\n").unwrap();
    let f = Fixture {
        module: std::env::var("PKCS11_TEST_KDF_MODULE").unwrap(),
        root,
        pin,
    };
    let salt = f.path("hybrid.salt");
    let info = f.path("hybrid.info");
    std::fs::write(&salt, b"CLI public salt").unwrap();
    for index in 0..3 {
        std::fs::write(
            &info,
            if index == 2 {
                b"other protocol".as_slice()
            } else {
                b"CLI hybrid protocol v1"
            },
        )
        .unwrap();
        let a = format!(
            "pkcs11:token=kdf-test;id=%F1%{:02X};type=secret-key",
            index % 2
        );
        let b = format!(
            "pkcs11:token=kdf-test;id=%F3%{:02X};type=secret-key",
            index % 2
        );
        let id = format!("d4{index:02x}");
        let args = [
            "derive-hybrid",
            "--object",
            &a,
            "--post-quantum",
            &b,
            "--digest",
            "sha512",
            "--kind",
            "aes256",
            "--salt-file",
            &salt,
            "--info-file",
            &info,
            "--id",
            &id,
            "--label",
            "CLI hybrid AES key",
            "--pin-file",
            &f.pin,
            "--confirm",
        ];
        assert_eq!(f.ok(&args)["derived"], true);
        f.fail(&args, 2);
    }
}
