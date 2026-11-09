// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI digest, MAC and AES block workflows on disposable SoftHSM.
//!
//! The runner provisions `client-test` with public test-vector secret keys.

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "pkcs11ctl-oasis-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
    fn pin(&self) -> PathBuf {
        self.file("pin", b"12345678")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .args(args)
        .output()
        .unwrap()
}

fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}

#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn digest_mac_and_aes_block_workflows() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let module = std::env::var("PKCS11_TEST_MODULE").unwrap();
    let scratch = Scratch::new();
    let pin = scratch.pin();
    let token = "pkcs11:token=client-test";
    let hmac = "pkcs11:token=client-test;object=hmac;type=secret-key";
    let cmac = "pkcs11:token=client-test;object=cmac;type=secret-key";
    let aes = "pkcs11:token=client-test;object=aes-cbc;type=secret-key";

    // SHA-256("abc").
    let message = scratch.file("abc", b"abc");
    let digest = scratch.0.join("digest");
    let output = run(&[
        "--module",
        &module,
        "digest",
        "--token",
        token,
        "--algorithm",
        "sha256",
        "--input",
        path(&message),
        "--output",
        path(&digest),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        hex(&std::fs::read(&digest).unwrap()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // HMAC-SHA-256 with key 00..1f.
    let message = scratch.file("message", b"The quick brown fox jumps over the lazy dog");
    let tag = scratch.0.join("tag");
    let output = run(&[
        "--module",
        &module,
        "mac",
        "--object",
        hmac,
        "--pin-file",
        path(&pin),
        "--algorithm",
        "hmac-sha256",
        "--input",
        path(&message),
        "--output",
        path(&tag),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        hex(&std::fs::read(&tag).unwrap()),
        "f87ad256151fc7b4c5dffa4adb3ebe911a8eeb8a8ebdee3c2a4a8e5f5ec02c32"
    );
    let output = run(&[
        "--module",
        &module,
        "verify-mac",
        "--object",
        hmac,
        "--pin-file",
        path(&pin),
        "--algorithm",
        "hmac-sha256",
        "--input",
        path(&message),
        "--tag",
        path(&tag),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tampered = scratch.file("tag-tampered", &[0u8; 32]);
    let output = run(&[
        "--module",
        &module,
        "verify-mac",
        "--object",
        hmac,
        "--pin-file",
        path(&pin),
        "--algorithm",
        "hmac-sha256",
        "--input",
        path(&message),
        "--tag",
        path(&tampered),
    ]);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("must-not-load"));

    // AES-CMAC RFC 4493.
    let message = scratch.file(
        "cmac-message",
        &hex_bytes("6bc1bee22e409f96e93d7e117393172a"),
    );
    let tag = scratch.0.join("cmac");
    let output = run(&[
        "--module",
        &module,
        "mac",
        "--object",
        cmac,
        "--pin-file",
        path(&pin),
        "--algorithm",
        "aes-cmac",
        "--input",
        path(&message),
        "--output",
        path(&tag),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        hex(&std::fs::read(&tag).unwrap()),
        "070a16b46b4d4144f79bdd9dd04a287c"
    );

    // AES-CBC NIST SP 800-38A.
    let plaintext = scratch.file("plaintext", &hex_bytes("6bc1bee22e409f96e93d7e117393172a"));
    let ciphertext = scratch.0.join("ciphertext");
    let output = run(&[
        "--module",
        &module,
        "encrypt-aes",
        "--object",
        aes,
        "--pin-file",
        path(&pin),
        "--mode",
        "cbc",
        "--iv",
        "000102030405060708090a0b0c0d0e0f",
        "--input",
        path(&plaintext),
        "--output",
        path(&ciphertext),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        hex(&std::fs::read(&ciphertext).unwrap()),
        "7649abac8119b246cee98e9b12e9197d"
    );
    let recovered = scratch.0.join("recovered");
    let output = run(&[
        "--module",
        &module,
        "decrypt-aes",
        "--object",
        aes,
        "--pin-file",
        path(&pin),
        "--mode",
        "cbc",
        "--iv",
        "000102030405060708090a0b0c0d0e0f",
        "--input",
        path(&ciphertext),
        "--output",
        path(&recovered),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&recovered).unwrap(),
        hex_bytes("6bc1bee22e409f96e93d7e117393172a")
    );

    // Generate HMAC and AES-CMAC keys, then use them through the same CLI.
    let output = run(&[
        "--module",
        &module,
        "generate",
        "--token",
        token,
        "--pin-file",
        path(&pin),
        "--kind",
        "hmac-sha256",
        "--id",
        "60",
        "--label",
        "generated-hmac",
        "--confirm",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let generated_hmac = "pkcs11:token=client-test;object=generated-hmac;type=secret-key";
    let message = scratch.file("generated-message", b"generated HMAC key");
    let tag = scratch.0.join("generated-tag");
    let output = run(&[
        "--module",
        &module,
        "mac",
        "--object",
        generated_hmac,
        "--pin-file",
        path(&pin),
        "--algorithm",
        "hmac-sha256",
        "--input",
        path(&message),
        "--output",
        path(&tag),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = run(&[
        "--module",
        &module,
        "verify-mac",
        "--object",
        generated_hmac,
        "--pin-file",
        path(&pin),
        "--algorithm",
        "hmac-sha256",
        "--input",
        path(&message),
        "--tag",
        path(&tag),
    ]);
    assert!(output.status.success());

    let output = run(&[
        "--module",
        &module,
        "generate",
        "--token",
        token,
        "--pin-file",
        path(&pin),
        "--kind",
        "aes128",
        "--purpose",
        "authentication",
        "--id",
        "61",
        "--label",
        "generated-cmac",
        "--confirm",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let generated_cmac = "pkcs11:token=client-test;object=generated-cmac;type=secret-key";
    let tag = scratch.0.join("generated-cmac-tag");
    let output = run(&[
        "--module",
        &module,
        "mac",
        "--object",
        generated_cmac,
        "--pin-file",
        path(&pin),
        "--algorithm",
        "aes-cmac",
        "--input",
        path(&message),
        "--output",
        path(&tag),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = run(&[
        "--module",
        &module,
        "verify-mac",
        "--object",
        generated_cmac,
        "--pin-file",
        path(&pin),
        "--algorithm",
        "aes-cmac",
        "--input",
        path(&message),
        "--tag",
        path(&tag),
    ]);
    assert!(output.status.success());

    // HashML-DSA is representable but this provider does not advertise it.
    let output = run(&[
        "--module",
        &module,
        "generate",
        "--token",
        token,
        "--pin-file",
        path(&pin),
        "--kind",
        "ml-dsa-44",
        "--id",
        "95",
        "--label",
        "hash-pqc-negative",
        "--confirm",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hash_message = scratch.file("hash-pqc-message", b"HashML-DSA negative fixture");
    let output = run(&[
        "--module",
        &module,
        "sign",
        "--key",
        "pkcs11:token=client-test;object=hash-pqc-negative;type=private",
        "--pin-file",
        path(&pin),
        "--algorithm",
        "hash-ml-dsa",
        "--parameter-set",
        "ml-dsa-44",
        "--digest",
        "sha256",
        "--input",
        path(&hash_message),
        "--output",
        "-",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("HashML-DSA") || stderr.contains("no permitted mechanism"),
        "{stderr}"
    );

    // SHA-224 is opt-in and works for RSA PKCS#1 and ECDSA.
    let sha224_message = scratch.file("sha224-message", b"SHA-224 signing fixture");
    for (algorithm, key_object) in [("rsa-pkcs1", "rsa"), ("ecdsa", "p256")] {
        let signature = scratch.0.join(format!("{algorithm}-sha224.sig"));
        let output = run(&[
            "--module",
            &module,
            "sign",
            "--key",
            &format!("pkcs11:token=client-test;object={key_object};type=private"),
            "--pin-file",
            path(&pin),
            "--algorithm",
            algorithm,
            "--digest",
            "sha224",
            "--allow-sha224",
            "--hashing",
            "software",
            "--input",
            path(&sha224_message),
            "--output",
            path(&signature),
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = run(&[
            "--module",
            &module,
            "verify",
            "--certificate",
            &format!("pkcs11:token=client-test;object={key_object};type=cert"),
            "--pin-file",
            path(&pin),
            "--algorithm",
            algorithm,
            "--digest",
            "sha224",
            "--allow-sha224",
            "--input",
            path(&sha224_message),
            "--signature",
            path(&signature),
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Multipart calls must match the single-part results.
    let multipart_digest = scratch.0.join("digest-multipart");
    let single_digest = scratch.0.join("digest-single-multipart");
    for (extra, destination) in [(true, &multipart_digest), (false, &single_digest)] {
        let mut args = vec![
            "--module",
            &module,
            "digest",
            "--token",
            token,
            "--algorithm",
            "sha256",
        ];
        if extra {
            args.push("--multipart");
        }
        args.extend(["--input", path(&message), "--output", path(destination)]);
        let output = run(&args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        std::fs::read(&multipart_digest).unwrap(),
        std::fs::read(&single_digest).unwrap()
    );
    let multipart_message = scratch.file("multipart-message", b"multipart message");
    let multipart_tag = scratch.0.join("multipart-tag");
    let output = run(&[
        "--module",
        &module,
        "mac",
        "--object",
        hmac,
        "--pin-file",
        path(&pin),
        "--algorithm",
        "hmac-sha256",
        "--multipart",
        "--input",
        path(&multipart_message),
        "--output",
        path(&multipart_tag),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let multipart_plaintext = scratch.file(
        "multipart-plaintext",
        &hex_bytes("6bc1bee22e409f96e93d7e117393172a"),
    );
    let multipart_ciphertext = scratch.0.join("multipart-ciphertext");
    let output = run(&[
        "--module",
        &module,
        "encrypt-aes",
        "--object",
        aes,
        "--pin-file",
        path(&pin),
        "--mode",
        "cbc",
        "--iv",
        "000102030405060708090a0b0c0d0e0f",
        "--multipart",
        "--input",
        path(&multipart_plaintext),
        "--output",
        path(&multipart_ciphertext),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&multipart_ciphertext).unwrap(),
        hex_bytes("7649abac8119b246cee98e9b12e9197d")
    );
    let multipart_recovered = scratch.0.join("multipart-recovered");
    let output = run(&[
        "--module",
        &module,
        "decrypt-aes",
        "--object",
        aes,
        "--pin-file",
        path(&pin),
        "--mode",
        "cbc",
        "--iv",
        "000102030405060708090a0b0c0d0e0f",
        "--multipart",
        "--input",
        path(&multipart_ciphertext),
        "--output",
        path(&multipart_recovered),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&multipart_recovered).unwrap(),
        hex_bytes("6bc1bee22e409f96e93d7e117393172a")
    );

    // Export a public key, import it under a new identity, and compare SPKI.
    for (source, id, label) in [
        ("rsa", "90", "imported-rsa"),
        ("p256", "91", "imported-p256"),
    ] {
        let exported = scratch.0.join(format!("{source}-export.der"));
        let output = run(&[
            "--module",
            &module,
            "export",
            "--object",
            &format!("pkcs11:token=client-test;object={source};type=public"),
            "--pin-file",
            path(&pin),
            "--output",
            path(&exported),
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = run(&[
            "--module",
            &module,
            "import",
            "--token",
            token,
            "--pin-file",
            path(&pin),
            "--kind",
            "public-key",
            "--purpose",
            "verification",
            "--id",
            id,
            "--label",
            label,
            "--input",
            path(&exported),
            "--confirm",
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let imported = scratch.0.join(format!("{source}-imported.der"));
        let output = run(&[
            "--module",
            &module,
            "export",
            "--object",
            &format!("pkcs11:token=client-test;object={label};type=public"),
            "--pin-file",
            path(&pin),
            "--output",
            path(&imported),
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(&exported).unwrap(),
            std::fs::read(&imported).unwrap()
        );
    }

    // Capability output distinguishes advertisement from execution.
    let output = run(&[
        "--module",
        &module,
        "--format",
        "json",
        "mechanisms",
        "--token",
        token,
    ]);
    assert!(output.status.success());
    let mechanisms: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        mechanisms["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| {
                entry["name"] == "CKM_AES_GCM"
                    && entry["executable"] == true
                    && entry["family"] == "aes"
            })
    );
    let output = run(&[
        "--module",
        &module,
        "--format",
        "json",
        "function-support",
        "--token",
        token,
    ]);
    assert!(output.status.success());
    let functions: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        functions["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["function"] == "GetInfo" && entry["supported"] == true })
    );
}

fn hex_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
