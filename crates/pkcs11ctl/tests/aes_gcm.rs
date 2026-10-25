// SPDX-License-Identifier: MIT OR Apache-2.0
//! Actual CLI AES-GCM file workflows on disposable providers.
use serde_json::Value;
use std::{
    path::PathBuf,
    process::{Command, Output},
};
struct Fixture {
    module: String,
    root: PathBuf,
    pin: String,
    token: String,
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
    fn ok(&self, args: &[&str]) -> Vec<u8> {
        let out = self.run(args);
        assert!(out.status.success(), "CLI status {}", out.status);
        assert!(out.stderr.is_empty());
        out.stdout
    }
    fn fail(&self, args: &[&str], code: i32) {
        let out = self.run(args);
        assert_eq!(out.status.code(), Some(code));
        assert!(out.stdout.is_empty());
        let error: Value = serde_json::from_slice(&out.stderr).unwrap();
        assert!(error["error"]["kind"].is_string());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("canary"));
    }
}
#[test]
#[ignore = "requires tools/test-softhsm.sh or tools/test-kem-hkdf.sh disposable store"]
fn file_encryption_authentication_and_output_contracts() {
    let kdf = std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref() == Ok("1");
    if !kdf {
        assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    }
    let root = PathBuf::from(
        std::env::var_os(if kdf {
            "PKCS11_TEST_KDF_DIR"
        } else {
            "PKCS11_CLIENT_TEST_DIR"
        })
        .unwrap(),
    )
    .join("cli-gcm");
    std::fs::create_dir(&root).unwrap();
    let pin = root.join("user.pin").to_str().unwrap().to_owned();
    std::fs::write(&pin, b"12345678\n").unwrap();
    let f = Fixture {
        module: std::env::var(if kdf {
            "PKCS11_TEST_KDF_MODULE"
        } else {
            "PKCS11_TEST_MODULE"
        })
        .unwrap(),
        root,
        pin,
        token: format!(
            "pkcs11:token={}",
            if kdf { "kdf-test" } else { "client-test" }
        ),
    };
    let input = f.path("plain");
    let aad = f.path("aad");
    std::fs::write(&input, b"CLI plaintext canary").unwrap();
    std::fs::write(&aad, b"public context").unwrap();
    for (index, kind) in ["aes128", "aes192", "aes256"].into_iter().enumerate() {
        let label = format!("cli-file-gcm-{index}");
        let id = format!("bc{index:02x}");
        f.ok(&[
            "generate",
            "--token",
            &f.token,
            "--kind",
            kind,
            "--purpose",
            "encryption",
            "--id",
            &id,
            "--label",
            &label,
            "--pin-file",
            &f.pin,
            "--confirm",
        ]);
        let object = format!("{};object={label};type=secret-key", f.token);
        let caps: Value = serde_json::from_slice(&f.ok(&[
            "aes-gcm-capabilities",
            "--object",
            &object,
            "--operation",
            "encrypt",
            "--pin-file",
            &f.pin,
        ]))
        .unwrap();
        assert_eq!(caps["result"]["tag_length"], 16);
        let cipher = f.path(&format!("cipher-{index}"));
        let output = f.path(&format!("plain-{index}"));
        let nonce = "0102030405060708090a0b0c";
        assert!(
            f.ok(&[
                "encrypt-aes-gcm",
                "--object",
                &object,
                "--nonce",
                nonce,
                "--aad-file",
                &aad,
                "--input",
                &input,
                "--output",
                &cipher,
                "--pin-file",
                &f.pin
            ])
            .is_empty()
        );
        assert_eq!(
            std::fs::read(&cipher).unwrap().len(),
            b"CLI plaintext canary".len() + 16
        );
        let decrypt = |nonce, aad: &str, input: &str, output: &str| {
            f.run(&[
                "decrypt-aes-gcm",
                "--object",
                &object,
                "--nonce",
                nonce,
                "--aad-file",
                aad,
                "--input",
                input,
                "--output",
                output,
                "--pin-file",
                &f.pin,
            ])
        };
        let out = decrypt(nonce, &aad, &cipher, &output);
        assert!(out.status.success());
        assert!(out.stdout.is_empty());
        assert_eq!(std::fs::read(&output).unwrap(), b"CLI plaintext canary");
        let out = decrypt(nonce, &aad, &cipher, "-");
        assert!(out.status.success());
        assert!(out.stderr.is_empty());
        assert_eq!(out.stdout, b"CLI plaintext canary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Existing outputs, including input aliases, are preserved before encryption runs.
        f.fail(
            &[
                "encrypt-aes-gcm",
                "--object",
                &object,
                "--nonce",
                "1112131415161718191a1b1c",
                "--input",
                &input,
                "--output",
                &input,
                "--pin-file",
                &f.pin,
            ],
            6,
        );
        assert_eq!(std::fs::read(&input).unwrap(), b"CLI plaintext canary");
        let corrupt = f.path(&format!("corrupt-{index}"));
        let mut bytes = std::fs::read(&cipher).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&corrupt, &bytes).unwrap();
        let wrong_aad = f.path("wrong-aad");
        std::fs::write(&wrong_aad, b"different context").unwrap();
        let truncated = f.path(&format!("truncated-{index}"));
        std::fs::write(&truncated, &bytes[..15]).unwrap();
        for (bad_nonce, bad_aad, bad_input, code) in [
            ("0202030405060708090a0b0c", aad.as_str(), cipher.as_str(), 5),
            (nonce, wrong_aad.as_str(), cipher.as_str(), 5),
            (nonce, aad.as_str(), corrupt.as_str(), 5),
            (nonce, aad.as_str(), truncated.as_str(), 2),
        ] {
            let failed = f.path(&format!("failed-{index}-{code}"));
            let out = decrypt(bad_nonce, bad_aad, bad_input, &failed);
            assert_eq!(out.status.code(), Some(code));
            assert!(out.stdout.is_empty());
            assert!(!std::path::Path::new(&failed).exists());
            assert!(!String::from_utf8_lossy(&out.stderr).contains("canary"));
            let out = decrypt(bad_nonce, bad_aad, bad_input, "-");
            assert_eq!(out.status.code(), Some(code));
            assert!(out.stdout.is_empty());
        }
        // Empty plaintext and absent AAD still produce a complete authentication tag.
        let empty = f.path("empty");
        std::fs::write(&empty, []).unwrap();
        let empty_cipher = f.path(&format!("empty-cipher-{index}"));
        f.ok(&[
            "encrypt-aes-gcm",
            "--object",
            &object,
            "--nonce",
            "2122232425262728292a2b2c",
            "--input",
            &empty,
            "--output",
            &empty_cipher,
            "--pin-file",
            &f.pin,
        ]);
        assert_eq!(std::fs::read(&empty_cipher).unwrap().len(), 16);
        let out = f.ok(&[
            "decrypt-aes-gcm",
            "--object",
            &object,
            "--nonce",
            "2122232425262728292a2b2c",
            "--input",
            &empty_cipher,
            "--output",
            "-",
            "--pin-file",
            &f.pin,
        ]);
        assert!(out.is_empty());
    }
}
