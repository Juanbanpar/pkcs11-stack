// SPDX-License-Identifier: MIT OR Apache-2.0
//! Multipart signature dispatch, authentication and checked output release.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/signature_stream_module.rs"]
mod module;
use module::SignatureStreamModule;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
struct Fixture {
    module: SignatureStreamModule,
    root: PathBuf,
    curve: u8,
}
impl Fixture {
    fn new(major: u8, minor: u8, fault: u8, curve: u8, auth: u8) -> Self {
        let module = SignatureStreamModule::new(major, minor, fault, curve, false, 224, auth);
        let root = module.path().parent().unwrap().join("cli");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("message"), b"abc").unwrap();
        std::fs::write(root.join("pin"), b"1234").unwrap();
        let size = match curve {
            0 => 256,
            1 => 64,
            2 => 96,
            _ => 132,
        };
        std::fs::write(root.join("signature"), vec![0xAB; size]).unwrap();
        Self {
            module,
            root,
            curve,
        }
    }
    fn path(&self, name: &str) -> String {
        self.root.join(name).to_str().unwrap().into()
    }
    fn run(
        &self,
        verify: bool,
        hashing: &str,
        input: &str,
        output: &str,
        stdin: Option<&[u8]>,
        extra: &[&str],
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command
            .arg("--module")
            .arg(self.module.path())
            .args([
                "--format",
                "json",
                if verify { "verify-token" } else { "sign" },
                "--key",
                if verify {
                    "pkcs11:token=cmac;id=%01;type=public"
                } else {
                    "pkcs11:token=cmac;id=%01;type=private"
                },
                "--algorithm",
                if self.curve == 0 {
                    "rsa-pkcs1"
                } else {
                    "ecdsa"
                },
                "--digest",
                "sha224",
                "--hashing",
                hashing,
                "--input",
                input,
                if verify { "--signature" } else { "--output" },
                output,
                "--multipart",
            ])
            .args(extra);
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
}
fn failure(output: Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("1234"));
}
#[test]
fn file_stdin_empty_and_context_authentication_across_versions() {
    for (major, minor) in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        for curve in 0..=3 {
            let f = Fixture::new(major, minor, 0, curve, 1);
            let output = f.path("output");
            failure(
                f.run(false, "token", &f.path("message"), &output, None, &[]),
                4,
            );
            assert!(!std::path::Path::new(&output).exists());
            let result = f.run(
                false,
                "token",
                &f.path("message"),
                &output,
                None,
                &["--context-pin-file", &f.path("pin")],
            );
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                std::fs::read(&output).unwrap(),
                std::fs::read(f.path("signature")).unwrap()
            );
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
            failure(
                f.run(false, "token", &f.path("message"), &output, None, &[]),
                6,
            );
            for bytes in [&b"abc"[..], &[][..]] {
                let result = f.run(
                    false,
                    "token",
                    "-",
                    "-",
                    Some(bytes),
                    &["--context-pin-file", &f.path("pin")],
                );
                assert!(result.status.success());
                assert_eq!(result.stdout, std::fs::read(f.path("signature")).unwrap());
                assert!(
                    f.run(true, "token", "-", &f.path("signature"), Some(bytes), &[])
                        .status
                        .success()
                );
            }
        }
    }
    let f = Fixture::new(3, 2, 0, 0, 2);
    assert!(
        f.run(
            false,
            "token",
            &f.path("message"),
            "-",
            None,
            &["--context-protected-path"]
        )
        .status
        .success()
    );
}
#[test]
fn pointer_gates_policies_native_errors_and_cleanup_withhold_output() {
    for (fault, verify, hashing, code) in [
        (20, false, "token", 5),
        (20, true, "token", 5),
        (23, false, "token", 5),
        (23, true, "token", 5),
        (25, false, "token", 5),
        (25, true, "token", 5),
        (25, false, "software", 5),
        (26, false, "token", 5),
        (27, false, "token", 5),
        (28, false, "token", 5),
        (29, true, "token", 4),
        (30, true, "token", 4),
        (31, false, "token", 4),
        (32, false, "token", 4),
        (33, true, "token", 4),
        (34, true, "token", 4),
        (40, false, "token", 4),
        (41, true, "token", 4),
        (42, false, "token", 4),
        (42, true, "token", 4),
        (49, false, "token", 5),
        (49, true, "token", 5),
        (50, false, "token", 5),
        (50, true, "token", 5),
    ] {
        let f = Fixture::new(3, 2, fault, 0, 0);
        let output = f.path("output");
        let signature = f.path("signature");
        failure(
            f.run(
                verify,
                hashing,
                &f.path("message"),
                if verify { &signature } else { &output },
                None,
                &[],
            ),
            code,
        );
        assert!(!std::path::Path::new(&output).exists());
        if !verify {
            failure(
                f.run(false, hashing, &f.path("message"), "-", None, &[]),
                code,
            );
        }
    }
    for (fault, verify, hashing) in [
        (35, false, "token"),
        (36, true, "token"),
        (31, false, "software"),
        (33, true, "software"),
        (42, false, "software"),
    ] {
        let f = Fixture::new(2, 40, fault, 0, 0);
        let signature = f.path("signature");
        let result = f.run(
            verify,
            hashing,
            &f.path("message"),
            if verify { &signature } else { "-" },
            None,
            &[],
        );
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
#[test]
fn preflight_and_stream_read_failures_preserve_inputs_and_remove_outputs() {
    let f = Fixture::new(3, 2, 0, 0, 0);
    let output = f.path("output");
    let huge = f.path("huge");
    std::fs::File::create(&huge)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    failure(f.run(false, "token", &huge, &output, None, &[]), 2);
    failure(
        f.run(
            false,
            "token",
            &f.path("message"),
            &output,
            None,
            &["--input-kind", "digest"],
        ),
        2,
    );
    failure(
        f.run(false, "token", f.root.to_str().unwrap(), &output, None, &[]),
        6,
    );
    failure(
        f.run(
            true,
            "token",
            f.root.to_str().unwrap(),
            &f.path("signature"),
            None,
            &[],
        ),
        6,
    );
    assert!(!std::path::Path::new(&output).exists());
    failure(
        f.run(
            false,
            "token",
            &f.path("message"),
            &f.path("message"),
            None,
            &[],
        ),
        6,
    );
    assert_eq!(std::fs::read(f.path("message")).unwrap(), b"abc");
    let bytes = vec![0x42; 64 * 1024 * 1024 + 1];
    failure(f.run(false, "software", "-", &output, Some(&bytes), &[]), 2);
    assert!(!std::path::Path::new(&output).exists());
    failure(
        f.run(
            true,
            "software",
            "-",
            &f.path("signature"),
            Some(&bytes),
            &[],
        ),
        2,
    );
}
