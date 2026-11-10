// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI EdDSA generation, signing and public export on disposable SoftHSM.

use pkcs11_client::EdDsaVerifyingKey;
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
            "pkcs11ctl-eddsa-{}-{}",
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

#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn cli_eddsa_generation_signing_and_export() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let module = std::env::var("PKCS11_TEST_MODULE").unwrap();
    let scratch = Scratch::new();
    let pin = scratch.file("pin", b"12345678");
    let message = scratch.file("message", b"CLI EdDSA provider fixture");
    for (kind, id, label) in [
        ("ed25519", "96", "cli-ed25519"),
        ("ed448", "97", "cli-ed448"),
    ] {
        let output = run(&[
            "--module",
            &module,
            "generate",
            "--token",
            "pkcs11:token=client-test",
            "--pin-file",
            path(&pin),
            "--kind",
            kind,
            "--id",
            id,
            "--label",
            label,
            "--confirm",
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let signature = scratch.0.join(format!("{kind}.sig"));
        let output = run(&[
            "--module",
            &module,
            "sign",
            "--key",
            &format!("pkcs11:token=client-test;object={label};type=private"),
            "--pin-file",
            path(&pin),
            "--algorithm",
            kind,
            "--input",
            path(&message),
            "--output",
            path(&signature),
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let spki = scratch.0.join(format!("{kind}.spki"));
        let output = run(&[
            "--module",
            &module,
            "export",
            "--object",
            &format!("pkcs11:token=client-test;object={label};type=public"),
            "--pin-file",
            path(&pin),
            "--key-family",
            "eddsa",
            "--output",
            path(&spki),
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let verifying = EdDsaVerifyingKey::from_spki_der(&std::fs::read(&spki).unwrap()).unwrap();
        let request = pkcs11_client::EdDsaRequest {
            curve: verifying.curve(),
            message: b"CLI EdDSA provider fixture",
        };
        verifying
            .verify_signature(&request, &std::fs::read(&signature).unwrap())
            .unwrap();
    }
}
