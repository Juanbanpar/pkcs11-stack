// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit multipart selection and output withheld through native cleanup.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/aes_gcm_stream_module.rs"]
mod module;
use module::AesGcmStreamModule;
use serde_json::Value;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
struct Fixture {
    module: AesGcmStreamModule,
    root: PathBuf,
}
impl Fixture {
    fn new(major: u8, minor: u8, fault: u8) -> Self {
        let module = AesGcmStreamModule::new(major, minor, fault, 16, 0);
        let root = module.path().parent().unwrap().join("cli");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("plain"), b"abc").unwrap();
        std::fs::write(root.join("cipher"), ciphertext()).unwrap();
        Self { module, root }
    }
    fn path(&self, name: &str) -> String {
        self.root.join(name).to_str().unwrap().into()
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command
            .arg("--module")
            .arg(self.module.path())
            .args(["--format", "json"]);
        command
    }
    fn run(
        &self,
        name: &str,
        multipart: bool,
        input: &str,
        output: &str,
        stdin: Option<&[u8]>,
    ) -> Output {
        let mut command = self.command();
        command.args([
            name,
            "--object",
            "pkcs11:token=cmac;id=%01;type=secret-key",
            "--nonce",
            "a5a5a5a5a5a5a5a5a5a5a5a5",
            "--input",
            input,
            "--output",
            output,
        ]);
        if multipart {
            command.arg("--multipart");
        }
        command
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        if let Some(bytes) = stdin {
            if let Err(error) = child.stdin.take().unwrap().write_all(bytes) {
                assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
            }
        }
        child.wait_with_output().unwrap()
    }
    fn capabilities(&self, multipart: bool) -> Output {
        let mut command = self.command();
        command.args([
            "aes-gcm-capabilities",
            "--object",
            "pkcs11:token=cmac;id=%01;type=secret-key",
            "--operation",
            "encrypt",
        ]);
        if multipart {
            command.arg("--multipart");
        }
        command.output().unwrap()
    }
}
fn ciphertext() -> Vec<u8> {
    b"abc"
        .iter()
        .map(|byte| byte ^ 0x80)
        .chain([0xEF; 16])
        .collect()
}
fn failure(output: Output, code: i32, kind: &str) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["kind"], kind);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("abc"));
}
#[test]
fn explicit_multipart_works_without_single_part_pointers_for_files_and_stdin() {
    for (major, minor) in [(2, 40), (3, 2)] {
        let f = Fixture::new(major, minor, 0);
        failure(f.capabilities(false), 4, "policy");
        let output = f.capabilities(true);
        assert!(output.status.success());
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["result"]["multipart"], true);
        assert_eq!(result["result"]["key_bits"], 128);
        let cipher = f.path("encrypted");
        let plain = f.path("decrypted");
        let output = f.run("encrypt-aes-gcm", false, &f.path("plain"), &cipher, None);
        failure(output, 4, "policy");
        assert!(!std::path::Path::new(&cipher).exists());
        let output = f.run("encrypt-aes-gcm", true, &f.path("plain"), &cipher, None);
        assert!(output.status.success());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert_eq!(std::fs::read(&cipher).unwrap(), ciphertext());
        let output = f.run("decrypt-aes-gcm", true, &cipher, &plain, None);
        assert!(output.status.success());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert_eq!(std::fs::read(&plain).unwrap(), b"abc");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&plain).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let output = f.run("encrypt-aes-gcm", true, "-", "-", Some(b"abc"));
        assert!(output.status.success());
        assert_eq!(output.stdout, ciphertext());
        assert!(output.stderr.is_empty());
        let output = f.run("decrypt-aes-gcm", true, "-", "-", Some(&ciphertext()));
        assert!(output.status.success());
        assert_eq!(output.stdout, b"abc");
        assert!(output.stderr.is_empty());
        let empty = f.path("empty");
        std::fs::write(&empty, []).unwrap();
        let output = f.run("encrypt-aes-gcm", true, &empty, "-", None);
        assert!(output.status.success());
        assert_eq!(output.stdout, vec![0xEF; 16]);
        let output = f.run("decrypt-aes-gcm", true, "-", "-", Some(&[0xEF; 16]));
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
    }
}
#[test]
fn authentication_native_and_cleanup_failures_never_release_binary_output() {
    for fault in [17, 18, 19, 20, 21, 22, 23, 26, 27, 36, 39, 40] {
        let f = Fixture::new(3, 2, fault);
        for (command, input) in [("encrypt-aes-gcm", "plain"), ("decrypt-aes-gcm", "cipher")] {
            if command == "encrypt-aes-gcm" && fault == 36 {
                continue;
            }
            let destination = f.path(command);
            failure(
                f.run(command, true, &f.path(input), &destination, None),
                5,
                "runtime",
            );
            assert!(!std::path::Path::new(&destination).exists());
            failure(
                f.run(command, true, &f.path(input), "-", None),
                5,
                "runtime",
            );
        }
    }
    // A provider may return plaintext from updates; it remains withheld on final failure.
    let f = Fixture::new(3, 2, 24);
    let output = f.run("decrypt-aes-gcm", true, &f.path("cipher"), "-", None);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"abc");
    for fault in [39, 40] {
        let f = Fixture::new(3, 2, fault);
        failure(
            f.run("decrypt-aes-gcm", true, "-", "-", Some(&[0; 15])),
            5,
            "runtime",
        );
    }
}
#[test]
fn existing_destinations_and_aliases_are_preserved_and_bad_inputs_are_removed() {
    let f = Fixture::new(3, 2, 0);
    let existing = f.path("existing");
    std::fs::write(&existing, b"preserve destination").unwrap();
    for command in ["encrypt-aes-gcm", "decrypt-aes-gcm"] {
        let input = if command == "encrypt-aes-gcm" {
            f.path("plain")
        } else {
            f.path("cipher")
        };
        failure(f.run(command, true, &input, &existing, None), 6, "io");
        assert_eq!(std::fs::read(&existing).unwrap(), b"preserve destination");
        let before = std::fs::read(&input).unwrap();
        failure(f.run(command, true, &input, &input, None), 6, "io");
        assert_eq!(std::fs::read(&input).unwrap(), before);
    }
    let short = f.path("short");
    std::fs::write(&short, [0; 15]).unwrap();
    let destination = f.path("failed");
    failure(
        f.run("decrypt-aes-gcm", true, &short, &destination, None),
        2,
        "input",
    );
    assert!(!std::path::Path::new(&destination).exists());
    failure(
        f.run("decrypt-aes-gcm", true, "-", &destination, Some(&[0; 15])),
        2,
        "input",
    );
    assert!(!std::path::Path::new(&destination).exists());
    let large = f.path("large");
    std::fs::File::create(&large)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    failure(
        f.run("encrypt-aes-gcm", true, &large, &destination, None),
        2,
        "input",
    );
    assert!(!std::path::Path::new(&destination).exists());
    // A directory opens as a file on Unix but fails only when the initialized reader reads it.
    failure(
        f.run(
            "encrypt-aes-gcm",
            true,
            f.root.to_str().unwrap(),
            &destination,
            None,
        ),
        6,
        "io",
    );
    assert!(!std::path::Path::new(&destination).exists());
    for fault in [11, 12, 14, 15] {
        let f = Fixture::new(3, 2, fault);
        let command = if fault <= 12 {
            "encrypt-aes-gcm"
        } else {
            "decrypt-aes-gcm"
        };
        let input = if fault <= 12 { "plain" } else { "cipher" };
        failure(f.run(command, true, &f.path(input), "-", None), 4, "policy");
    }
}
