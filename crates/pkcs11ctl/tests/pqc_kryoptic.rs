// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI HashSLH-DSA and Montgomery workflows on disposable Kryoptic.

use pkcs11_client::{
    Authentication, HashInput, HashSlhDsaRequest, Pin, Provider, PublicKeyRef, SigningPolicy,
    SlhDsaHedging, SlhDsaParameterSet,
};
use secrecy::SecretString;
use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::Command,
};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "pkcs11ctl-pqc-kryoptic-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
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
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .args(args)
        .output()
        .unwrap()
}
fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}
fn success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires tools/test-pqc-kryoptic.sh disposable store"]
fn hash_slh_dsa_and_montgomery_cli_workflows() {
    assert_eq!(
        std::env::var("PKCS11_TEST_PQC_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = std::env::var("PKCS11_TEST_PQC_MODULE").unwrap();
    let scratch = Scratch::new();
    let pin = scratch.pin();
    let token = "pkcs11:token=pqc-test";

    let generated = run(&[
        "--module",
        &module,
        "generate",
        "--token",
        token,
        "--pin-file",
        path(&pin),
        "--kind",
        "hash-slh-dsa-sha2-128f",
        "--id",
        "c1",
        "--label",
        "cli-hash-slh",
        "--confirm",
    ]);
    success(&generated);

    let message = scratch.file("hash-slh-message", b"CLI HashSLH-DSA provider message");
    let signature = scratch.0.join("hash-slh-signature");
    let signed = run(&[
        "--module",
        &module,
        "sign",
        "--key",
        "pkcs11:token=pqc-test;object=cli-hash-slh;type=private",
        "--pin-file",
        path(&pin),
        "--algorithm",
        "hash-slh-dsa",
        "--parameter-set",
        "slh-dsa-sha2-128f",
        "--digest",
        "sha256",
        "--input",
        path(&message),
        "--output",
        path(&signature),
    ]);
    success(&signed);
    let signature = std::fs::read(&signature).unwrap();
    assert_eq!(
        signature.len(),
        SlhDsaParameterSet::Sha2_128F.signature_length()
    );

    let provider = Provider::load(&module).unwrap();
    let client = provider
        .client(
            &token.parse().unwrap(),
            NonZeroUsize::new(1).unwrap(),
            SigningPolicy::default(),
        )
        .unwrap();
    let public = PublicKeyRef::new(
        "pkcs11:token=pqc-test;object=cli-hash-slh;type=public"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let user_pin = SecretString::from("12345678");
    client
        .verify_hash_slh_dsa(
            &public,
            &HashSlhDsaRequest {
                parameter_set: SlhDsaParameterSet::Sha2_128F,
                input: HashInput::Message {
                    hash: pkcs11_client::PrehashAlgorithm::Sha256,
                    message: &std::fs::read(&message).unwrap(),
                },
                context: b"",
                hedging: SlhDsaHedging::Deterministic,
            },
            &signature,
            Authentication::User(Pin::Value(&user_pin)),
        )
        .unwrap();
    client.close().unwrap();

    for (label, id) in [("cli-mont-a", "c2"), ("cli-mont-b", "c3")] {
        let generated = run(&[
            "--module",
            &module,
            "generate",
            "--token",
            token,
            "--pin-file",
            path(&pin),
            "--kind",
            "x25519",
            "--id",
            id,
            "--label",
            label,
            "--confirm",
        ]);
        success(&generated);
    }
    let a_public = scratch.0.join("cli-mont-a.der");
    let b_public = scratch.0.join("cli-mont-b.der");
    for (label, output) in [("cli-mont-a", &a_public), ("cli-mont-b", &b_public)] {
        let exported = run(&[
            "--module",
            &module,
            "export",
            "--object",
            &format!("pkcs11:token=pqc-test;object={label};type=public"),
            "--key-family",
            "montgomery",
            "--pin-file",
            path(&pin),
            "--output",
            path(output),
        ]);
        success(&exported);
    }
    for (label, peer, id) in [
        ("cli-mont-a", &b_public, "c4"),
        ("cli-mont-b", &a_public, "c5"),
    ] {
        let derived = run(&[
            "--module",
            &module,
            "derive-montgomery",
            "--object",
            &format!("pkcs11:token=pqc-test;object={label};type=private"),
            "--curve",
            "x25519",
            "--peer",
            path(peer),
            "--kdf",
            "x963-sha256",
            "--kind",
            "aes128",
            "--id",
            id,
            "--label",
            &format!("{label}-derived"),
            "--confirm",
            "--pin-file",
            path(&pin),
        ]);
        success(&derived);
    }

    let plaintext = scratch.file("montgomery-plaintext", b"CLI Montgomery agreement");
    let ciphertext = scratch.0.join("montgomery-ciphertext");
    let decrypted = scratch.0.join("montgomery-decrypted");
    let encrypted = run(&[
        "--module",
        &module,
        "encrypt-aes",
        "--object",
        "pkcs11:token=pqc-test;object=cli-mont-a-derived;type=secret-key",
        "--mode",
        "cbc-pad",
        "--iv",
        "00000000000000000000000000000000",
        "--input",
        path(&plaintext),
        "--output",
        path(&ciphertext),
        "--pin-file",
        path(&pin),
    ]);
    success(&encrypted);
    let decrypted_output = run(&[
        "--module",
        &module,
        "decrypt-aes",
        "--object",
        "pkcs11:token=pqc-test;object=cli-mont-b-derived;type=secret-key",
        "--mode",
        "cbc-pad",
        "--iv",
        "00000000000000000000000000000000",
        "--input",
        path(&ciphertext),
        "--output",
        path(&decrypted),
        "--pin-file",
        path(&pin),
    ]);
    success(&decrypted_output);
    assert_eq!(
        std::fs::read(&decrypted).unwrap(),
        b"CLI Montgomery agreement"
    );
}
