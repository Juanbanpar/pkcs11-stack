// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure ML-DSA CLI parameters, interface gates and checked output release.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/ml_dsa_stream_module.rs"]
mod signing;
#[path = "../../pkcs11-runtime/tests/fixtures/ml_dsa_verify_module.rs"]
mod verification;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
enum Module {
    Sign(signing::MlDsaStreamModule),
    Verify(verification::MlDsaVerifyModule),
}
impl Module {
    fn path(&self) -> PathBuf {
        match self {
            Self::Sign(m) => m.path(),
            Self::Verify(m) => m.path(),
        }
    }
}
struct Fixture {
    module: Module,
    root: PathBuf,
    parameter: u8,
    sign: bool,
    context: usize,
    auth: bool,
}
impl Fixture {
    fn new(
        sign: bool,
        version: (u8, u8),
        fault: u8,
        parameter: u8,
        context: usize,
        auth: bool,
    ) -> Self {
        let module = if sign {
            Module::Sign(signing::MlDsaStreamModule::new(
                version.0,
                version.1,
                fault,
                parameter,
                1,
                context,
                u8::from(auth),
            ))
        } else {
            Module::Verify(verification::MlDsaVerifyModule::new(
                version.0, version.1, fault, parameter, 1, context,
            ))
        };
        let root = module.path().parent().unwrap().join("cli");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("message"), b"abc").unwrap();
        std::fs::write(root.join("context"), vec![0xA5; context]).unwrap();
        std::fs::write(root.join("pin"), b"1234").unwrap();
        std::fs::write(
            root.join("signature"),
            vec![0xAB; [2420, 3309, 4627][usize::from(parameter)]],
        )
        .unwrap();
        Self {
            module,
            root,
            parameter,
            sign,
            context,
            auth,
        }
    }
    fn path(&self, name: &str) -> String {
        self.root.join(name).to_str().unwrap().into()
    }
    fn run(&self, multipart: bool, input: &str, output: &str, stdin: Option<&[u8]>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"));
        command.arg("--module").arg(self.module.path()).args([
            "--format",
            "json",
            if self.sign { "sign" } else { "verify-token" },
            "--key",
            if self.sign {
                "pkcs11:token=cmac;id=%01;type=private"
            } else {
                "pkcs11:token=cmac;id=%01;type=public"
            },
            "--algorithm",
            ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"][usize::from(self.parameter)],
            "--input",
            input,
            if self.sign { "--output" } else { "--signature" },
            output,
        ]);
        if multipart {
            command.arg("--multipart");
        }
        if self.context > 0 {
            command.args(["--context-file", &self.path("context")]);
        }
        if self.auth {
            command.args(["--context-pin-file", &self.path("pin")]);
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
fn exact_parameters_original_chunks_empty_stdin_and_interface_gates() {
    for parameter in 0..3 {
        for version in [(2, 40), (3, 0), (3, 1), (3, 2)] {
            let f = Fixture::new(true, version, 10, parameter, 255, true);
            let output = f.path("output");
            assert!(f.run(false, &f.path("message"), "-", None).status.success());
            assert!(!std::path::Path::new(&output).exists());
            let result = f.run(true, &f.path("message"), &output, None);
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
            failure(f.run(true, &f.path("message"), &output, None), 6);
            for input in [&b"abc"[..], &[][..]] {
                let result = f.run(true, "-", "-", Some(input));
                assert!(result.status.success());
                assert_eq!(result.stdout, std::fs::read(f.path("signature")).unwrap());
            }
            let f = Fixture::new(false, version, 0, parameter, 255, false);
            failure(
                f.run(false, &f.path("message"), &f.path("signature"), None),
                5,
            );
            for input in [&b"abc"[..], &[][..]] {
                let result = f.run(true, "-", &f.path("signature"), Some(input));
                if version == (3, 2) {
                    assert!(
                        result.status.success(),
                        "{}",
                        String::from_utf8_lossy(&result.stderr)
                    );
                } else {
                    failure(result, 4);
                }
            }
        }
    }
}
#[test]
fn native_failures_and_cleanup_withhold_output_without_retry() {
    for (sign, fault, code) in [
        (true, 2, 4),
        (true, 8, 4),
        (true, 9, 4),
        (true, 11, 5),
        (true, 13, 5),
        (true, 15, 5),
        (true, 16, 5),
        (true, 17, 5),
        (true, 18, 5),
        (true, 21, 5),
        (true, 28, 5),
        (true, 29, 5),
        (false, 2, 4),
        (false, 6, 4),
        (false, 8, 4),
        (false, 9, 4),
        (false, 11, 5),
        (false, 13, 5),
        (false, 15, 5),
        (false, 16, 4),
        (false, 17, 4),
        (false, 21, 5),
        (false, 33, 5),
        (false, 34, 5),
        (false, 35, 5),
        (false, 36, 5),
    ] {
        let f = Fixture::new(sign, (3, 2), fault, 0, 0, false);
        let output = f.path("output");
        let signature = f.path("signature");
        failure(
            f.run(
                true,
                &f.path("message"),
                if sign { &output } else { &signature },
                None,
            ),
            code,
        );
        assert!(!std::path::Path::new(&output).exists());
        if sign {
            failure(f.run(true, &f.path("message"), "-", None), code);
        }
    }
}
#[test]
fn input_budgets_read_errors_and_output_aliases_are_checked() {
    for sign in [false, true] {
        let f = Fixture::new(sign, (3, 2), if sign { 30 } else { 37 }, 0, 0, false);
        let output = f.path("output");
        let signature = f.path("signature");
        let destination = if sign { &output } else { &signature };
        failure(f.run(true, f.root.to_str().unwrap(), destination, None), 6);
        assert!(!std::path::Path::new(&output).exists());
        let huge = f.path("huge");
        std::fs::File::create(&huge)
            .unwrap()
            .set_len(64 * 1024 * 1024 + 1)
            .unwrap();
        failure(f.run(true, &huge, destination, None), 2);
        let bytes = vec![0x42; 64 * 1024 * 1024 + 1];
        assert!(
            f.run(
                true,
                "-",
                if sign { "-" } else { &signature },
                Some(&bytes[..bytes.len() - 1])
            )
            .status
            .success()
        );
        failure(f.run(true, "-", destination, Some(&bytes)), 2);
        assert!(!std::path::Path::new(&output).exists());
        if sign {
            failure(f.run(true, &f.path("message"), &f.path("message"), None), 6);
            assert_eq!(std::fs::read(f.path("message")).unwrap(), b"abc");
        }
    }
}
