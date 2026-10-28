// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure EdDSA CLI input contracts and disposable-provider workflows.
use serde_json::Value;
use std::{
    path::PathBuf,
    process::{Command, Output},
};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pkcs11ctl"))
        .args(["--format", "json"])
        .args(args)
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> Value {
    let output = run(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pkcs11-client/tests/fixtures/eddsa")
        .join(name)
}
#[test]
fn offline_certificate_verification_and_rejection_of_hash_context_and_prehash_options() {
    for curve in ["ed25519", "ed448"] {
        let input = fixture("message.txt");
        let signature = fixture(&format!("{curve}.sig"));
        let certificate = fixture(&format!("{curve}.der"));
        let args = [
            "verify",
            "--algorithm",
            curve,
            "--certificate-file",
            certificate.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
        ];
        assert_eq!(ok(&args)["result"]["verified"], true);
        for extra in [
            ["--digest", "sha512"],
            ["--mgf-digest", "sha512"],
            ["--salt-length", "32"],
            ["--input-kind", "digest"],
            ["--context-file", "missing"],
        ] {
            let mut invalid = args.to_vec();
            invalid.extend(extra);
            let output = run(&invalid);
            assert_eq!(
                output.status.code(),
                Some(2),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stdout.is_empty());
        }
        let output = run(&[
            "--module",
            "missing-library",
            "sign",
            "--key",
            "pkcs11:token=missing;id=%01;type=private",
            "--algorithm",
            curve,
            "--input",
            input.to_str().unwrap(),
            "--output",
            "-",
            "--hashing",
            "software",
        ]);
        assert_eq!(output.status.code(), Some(2));
    }
}
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn pure_eddsa_cli_generation_signing_import_and_native_verification() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    if std::env::var("PKCS11_TEST_REQUIRE_EDDSA").as_deref() != Ok("1") {
        return;
    }
    let module = std::env::var("PKCS11_TEST_MODULE").unwrap();
    let root = PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
    let pin = root.join("eddsa-cli.pin");
    std::fs::write(&pin, b"12345678\n").unwrap();
    let input = fixture("message.txt");
    for (index, curve) in ["ed25519", "ed448"].into_iter().enumerate() {
        let label = format!("cli-{curve}");
        let id = format!("D7ED0{index}");
        let private = format!("pkcs11:token=client-test;object={label};type=private");
        let public = format!("pkcs11:token=client-test;object={label};type=public");
        let output = root.join(format!("cli-{curve}.sig"));
        let spki = root.join(format!("cli-{curve}.spki"));
        let base = ["--module", module.as_str()];
        let call = |args: &[&str]| {
            let mut all = base.to_vec();
            all.extend_from_slice(args);
            ok(&all)
        };
        call(&[
            "generate",
            "--token",
            "pkcs11:token=client-test",
            "--kind",
            curve,
            "--id",
            &id,
            "--label",
            &label,
            "--always-authenticate",
            "--confirm",
            "--pin-file",
            pin.to_str().unwrap(),
        ]);
        assert_eq!(
            call(&[
                "capabilities",
                "--key",
                &private,
                "--key-family",
                "eddsa",
                "--pin-file",
                pin.to_str().unwrap()
            ])["result"]["always_authenticate"],
            true
        );
        let sign = [
            "sign",
            "--key",
            &private,
            "--algorithm",
            curve,
            "--input",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--pin-file",
            pin.to_str().unwrap(),
            "--context-pin-file",
            pin.to_str().unwrap(),
        ];
        let mut all = base.to_vec();
        all.extend(sign);
        let signed = run(&all);
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
        let mut export = base.to_vec();
        export.extend([
            "export",
            "--object",
            &public,
            "--key-family",
            "eddsa",
            "--output",
            spki.to_str().unwrap(),
        ]);
        let exported = run(&export);
        assert!(
            exported.status.success(),
            "{}",
            String::from_utf8_lossy(&exported.stderr)
        );
        call(&[
            "verify-token",
            "--key",
            &public,
            "--algorithm",
            curve,
            "--input",
            input.to_str().unwrap(),
            "--signature",
            output.to_str().unwrap(),
        ]);
        let imported_label = format!("import-{label}");
        let imported_id = format!("D7ED1{index}");
        call(&[
            "import",
            "--kind",
            "eddsa",
            "--purpose",
            "verification",
            "--token",
            "pkcs11:token=client-test",
            "--input",
            spki.to_str().unwrap(),
            "--id",
            &imported_id,
            "--label",
            &imported_label,
            "--confirm",
            "--pin-file",
            pin.to_str().unwrap(),
        ]);
        call(&[
            "verify-token",
            "--key",
            &format!("pkcs11:token=client-test;object={imported_label};type=public"),
            "--algorithm",
            curve,
            "--input",
            input.to_str().unwrap(),
            "--signature",
            output.to_str().unwrap(),
        ]);
        let protected = std::fs::read(&output).unwrap();
        let failed = run(&all);
        assert!(!failed.status.success());
        assert_eq!(std::fs::read(output).unwrap(), protected);
    }
}
