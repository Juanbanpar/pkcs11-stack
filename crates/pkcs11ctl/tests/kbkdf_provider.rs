// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI SP 800-108 derivation on a disposable Kryoptic store.

use pkcs11_client::{Attribute, Authentication, KeyType, Module, ObjectClass, Pin, SessionMode};
use secrecy::SecretString;
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
            "pkcs11ctl-kbkdf-{}-{}",
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

fn create_base(module_path: &str) {
    let module = Module::load(module_path).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let pin = SecretString::from("12345678");
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    session
        .create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Derive(true),
            Attribute::Id(b"kbkdf-cli-base".to_vec()),
            Attribute::Label(b"kbkdf-cli-base".to_vec()),
            Attribute::Value(vec![0x0B; 32]),
        ])
        .unwrap();
}

#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn cli_derives_usable_keys_and_preserves_output_contracts() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = std::env::var("PKCS11_TEST_KDF_MODULE").unwrap();
    create_base(&module);
    let scratch = Scratch::new();
    let pin = scratch.file("pin", b"12345678");
    let label = scratch.file("label", b"cli kbkdf label");
    let context = scratch.file("context", b"cli kbkdf context");
    let base = "pkcs11:token=kdf-test;object=kbkdf-cli-base;type=secret-key";
    for (id, output) in [("70", "derived-a"), ("71", "derived-b")] {
        let out = run(&[
            "--module",
            &module,
            "derive-kbkdf",
            "--object",
            base,
            "--pin-file",
            path(&pin),
            "--prf",
            "hmac-sha256",
            "--mode",
            "counter",
            "--kind",
            "aes256",
            "--kdf-label-file",
            path(&label),
            "--kdf-context-file",
            path(&context),
            "--id",
            id,
            "--label",
            output,
            "--confirm",
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let one = "pkcs11:token=kdf-test;object=derived-a;type=secret-key";
    let two = "pkcs11:token=kdf-test;object=derived-b;type=secret-key";
    let plaintext = scratch.file("plaintext", &[9u8; 16]);
    let ciphertext = scratch.0.join("ciphertext");
    let out = run(&[
        "--module",
        &module,
        "encrypt-aes",
        "--object",
        one,
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
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let recovered = scratch.0.join("recovered");
    let out = run(&[
        "--module",
        &module,
        "decrypt-aes",
        "--object",
        two,
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
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&recovered).unwrap(), vec![9u8; 16]);

    // Counter mode rejects an external IV before any provider call.
    let out = run(&[
        "--module",
        &module,
        "derive-kbkdf",
        "--object",
        base,
        "--pin-file",
        path(&pin),
        "--prf",
        "hmac-sha256",
        "--mode",
        "counter",
        "--kind",
        "aes256",
        "--iv",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--id",
        "72",
        "--label",
        "invalid",
        "--confirm",
    ]);
    assert!(!out.status.success());
}
