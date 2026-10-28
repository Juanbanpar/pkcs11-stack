// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native multipart selection, input bounds and checked output commit.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/mac_stream_module.rs"]
mod module;
use module::MacStreamModule;
use serde_json::Value;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

struct Fixture {
    module: MacStreamModule,
    root: PathBuf,
    hmac: bool,
    general: bool,
}
impl Fixture {
    fn new(major: u8, minor: u8, fault: u8, hmac: bool, general: bool) -> Self {
        let module = MacStreamModule::new(major, minor, fault, hmac, general);
        let root = module.path().parent().unwrap().join("cli");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("message"), b"mac-input-canary").unwrap();
        let length = match (hmac, general) {
            (true, false) => 32,
            (true, true) | (false, false) => 16,
            _ => 8,
        };
        std::fs::write(root.join("tag"), vec![0xAB; length]).unwrap();
        Self {
            module,
            root,
            hmac,
            general,
        }
    }
    fn path(&self, name: &str) -> String {
        self.root.join(name).to_str().unwrap().into()
    }
    fn run(
        &self,
        verify: bool,
        multipart: bool,
        input: &str,
        output: &str,
        stdin: Option<&[u8]>,
    ) -> Output {
        let name = match (self.hmac, verify) {
            (true, false) => "mac-hmac",
            (true, true) => "verify-hmac",
            (false, false) => "mac-aes-cmac",
            (false, true) => "verify-aes-cmac",
        };
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command.arg("--module").arg(self.module.path()).args([
            "--format",
            "json",
            name,
            "--object",
            "pkcs11:token=cmac;id=%01;type=secret-key",
            "--input",
            input,
        ]);
        if self.hmac {
            command.args(["--algorithm", "hmac-sha256"]);
        }
        if self.general {
            command.args(["--tag-length", if self.hmac { "16" } else { "8" }]);
        }
        if multipart {
            command.arg("--multipart");
        }
        command.args([if verify { "--tag-file" } else { "--output" }, output]);
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
    assert!(!String::from_utf8_lossy(&output.stderr).contains("mac-input-canary"));
}
#[test]
fn multipart_files_stdin_and_empty_messages_work_without_single_part_pointers() {
    for (major, minor) in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        for (hmac, general) in [(true, false), (true, true), (false, false), (false, true)] {
            let f = Fixture::new(major, minor, 0, hmac, general);
            let input = f.path("message");
            let tag = f.path("tag");
            let output = f.path("output");
            failure(f.run(false, false, &input, &output, None), 4, "policy");
            assert!(!std::path::Path::new(&output).exists());
            failure(f.run(true, false, &input, &tag, None), 4, "policy");
            let result = f.run(false, true, &input, &output, None);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                std::fs::read(&output).unwrap(),
                std::fs::read(&tag).unwrap()
            );
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
            for message in [&[][..], &b"mac-input-canary"[..]] {
                let result = f.run(false, true, "-", "-", Some(message));
                assert!(result.status.success());
                assert_eq!(result.stdout, std::fs::read(&tag).unwrap());
                let result = f.run(true, true, "-", &tag, Some(message));
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let value: Value = serde_json::from_slice(&result.stdout).unwrap();
                assert_eq!(value["result"]["verified"], true);
            }
            failure(f.run(false, true, &input, &output, None), 6, "io");
            assert_eq!(
                std::fs::read(&output).unwrap(),
                std::fs::read(&tag).unwrap()
            );
            failure(f.run(false, true, &input, &input, None), 6, "io");
            assert_eq!(std::fs::read(&input).unwrap(), b"mac-input-canary");
        }
    }
}
#[test]
fn native_failures_and_cleanup_withhold_tags_and_verification_success() {
    for hmac in [false, true] {
        for (fault, verify, code, kind) in [
            (12, false, 4, "policy"),
            (13, true, 4, "policy"),
            (20, false, 5, "runtime"),
            (20, true, 5, "runtime"),
            (21, false, 5, "runtime"),
            (21, true, 5, "runtime"),
            (23, false, 5, "runtime"),
            (23, true, 5, "runtime"),
            (24, false, 5, "runtime"),
            (25, false, 5, "runtime"),
            (26, false, 5, "runtime"),
            (27, true, 4, "client"),
            (28, true, 4, "client"),
            (29, false, 4, "policy"),
            (30, false, 4, "policy"),
            (31, true, 4, "policy"),
            (32, true, 4, "policy"),
            (37, false, 5, "runtime"),
            (37, true, 5, "runtime"),
            (38, false, 5, "runtime"),
            (38, true, 5, "runtime"),
        ] {
            let f = Fixture::new(3, 2, fault, hmac, true);
            let output = f.path("output");
            let tag = f.path("tag");
            failure(
                f.run(
                    verify,
                    true,
                    &f.path("message"),
                    if verify { &tag } else { &output },
                    None,
                ),
                code,
                kind,
            );
            assert!(!std::path::Path::new(&output).exists());
            if !verify {
                failure(
                    f.run(false, true, &f.path("message"), "-", None),
                    code,
                    kind,
                );
            }
        }
    }
}
#[test]
fn preflight_read_failures_and_stream_overruns_release_no_output() {
    for hmac in [false, true] {
        let f = Fixture::new(2, 40, 0, hmac, false);
        let output = f.path("output");
        let oversize = f.path("oversize");
        std::fs::File::create(&oversize)
            .unwrap()
            .set_len(16 * 1024 * 1024 + 1)
            .unwrap();
        failure(f.run(false, true, &oversize, &output, None), 2, "input");
        assert!(!std::path::Path::new(&output).exists());
        failure(
            f.run(false, true, &f.path("missing"), &output, None),
            6,
            "io",
        );
        failure(
            f.run(false, true, f.root.to_str().unwrap(), &output, None),
            6,
            "io",
        );
        assert!(!std::path::Path::new(&output).exists());
        failure(
            f.run(true, true, f.root.to_str().unwrap(), &f.path("tag"), None),
            6,
            "io",
        );
        let bytes = vec![0x42; 16 * 1024 * 1024 + 1];
        let result = f.run(false, true, "-", "-", Some(&bytes[..bytes.len() - 1]));
        assert!(result.status.success());
        failure(f.run(false, true, "-", &output, Some(&bytes)), 2, "input");
        assert!(!std::path::Path::new(&output).exists());
        failure(
            f.run(true, true, "-", &f.path("tag"), Some(&bytes)),
            2,
            "input",
        );
        std::fs::write(f.path("tag"), []).unwrap();
        failure(
            f.run(true, true, &f.path("missing"), &f.path("tag"), None),
            2,
            "input",
        );
    }
}
