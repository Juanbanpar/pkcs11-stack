// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI binary password workflow and agreement with OpenSSL-checked runtime keys.
use std::process::Command;
#[test]
#[ignore = "requires isolated tools/test-kem-hkdf.sh provider"]
fn pbkdf2_cli_prfs_protected_outputs_and_runtime_agreement() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let root = std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap())
        .join("cli-pbkdf2");
    std::fs::create_dir(&root).unwrap();
    let password = root.join("password");
    let salt = root.join("salt");
    let pin = root.join("pin");
    let plain = root.join("plain");
    std::fs::write(&password, [b'p', 0, 0xff, b'\n']).unwrap();
    std::fs::write(&salt, b"salt").unwrap();
    std::fs::write(&pin, b"12345678\n").unwrap();
    std::fs::write(&plain, b"CLI PBKDF2 agreement").unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
            .arg("--module")
            .arg(&module)
            .args(["--format", "json"])
            .args(args)
            .arg("--pin-file")
            .arg(&pin)
            .output()
            .unwrap()
    };
    let ok = |args: &[&str]| {
        let out = run(args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        if out.stdout.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["result"].clone()
        }
    };
    assert_eq!(
        ok(&["pbkdf2-capabilities", "--token", "pkcs11:token=kdf-test"])["generate"],
        true
    );
    for (i, digest) in [
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha512-224",
        "sha512-256",
    ]
    .into_iter()
    .enumerate()
    {
        for kind in ["aes256", "derivation-secret"] {
            let id = format!("fab4{i:02x}{}", if kind == "aes256" { "00" } else { "01" });
            let object = format!(
                "pkcs11:token=kdf-test;id=%FA%B4%{i:02X}%{};type=secret-key",
                if kind == "aes256" { "00" } else { "01" }
            );
            let mut args = vec![
                "generate-pbkdf2",
                "--token",
                "pkcs11:token=kdf-test",
                "--password-file",
                password.to_str().unwrap(),
                "--salt-file",
                salt.to_str().unwrap(),
                "--digest",
                digest,
                "--iterations",
                "2",
                "--kind",
                kind,
                "--id",
                &id,
                "--label",
                "CLI PBKDF2",
                "--confirm",
            ];
            if kind == "derivation-secret" {
                args.extend(["--length", "65"]);
            }
            let result = ok(&args);
            assert_eq!(result["generated"], true);
            assert_eq!(result["extractable"], false);
            assert_eq!(run(&args).status.code(), Some(2));
            if kind == "aes256" {
                let cipher = root.join(format!("cipher-{i}"));
                let recovered = root.join(format!("recovered-{i}"));
                let nonce = format!("{i:02x}").repeat(12);
                ok(&[
                    "encrypt-aes-gcm",
                    "--object",
                    &object,
                    "--nonce",
                    &nonce,
                    "--input",
                    plain.to_str().unwrap(),
                    "--output",
                    cipher.to_str().unwrap(),
                ]);
                let canonical = format!("pkcs11:token=kdf-test;id=%FA%B0%{i:02X};type=secret-key");
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
                assert_eq!(std::fs::read(recovered).unwrap(), b"CLI PBKDF2 agreement");
                std::fs::remove_file(cipher).unwrap();
            }
            ok(&["delete", "--object", &object, "--confirm"]);
        }
    }
}
