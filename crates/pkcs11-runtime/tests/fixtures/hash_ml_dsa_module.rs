// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disposable HashML-DSA module compiled with the requested official headers.
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

/// Locally compiled fixture; does not access operator token stores.
pub struct HashMlDsaModule(PathBuf);
impl HashMlDsaModule {
    #[allow(clippy::too_many_arguments)]
    /// Compile the exact table layout and selected failure path.
    pub fn new(
        major: u8,
        minor: u8,
        fault: u8,
        parameter: u8,
        hedge: u8,
        context_length: usize,
        auth: u8,
        prehash: bool,
        verify: bool,
    ) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pkcs11-hash-mldsa-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let fixture = Self(dir);
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkcs11-runtime/tests/fixtures");
        let output = Command::new("cc")
            .args([
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fPIC",
                if cfg!(target_os = "macos") {
                    "-dynamiclib"
                } else {
                    "-shared"
                },
            ])
            .arg(format!("-DAPI_MAJOR={major}"))
            .arg(format!("-DAPI_MINOR={minor}"))
            .arg(format!("-DFAULT={fault}"))
            .arg(format!("-DPARAMETER={parameter}"))
            .arg(format!("-DHEDGE={hedge}"))
            .arg(format!("-DCONTEXT_LENGTH={context_length}"))
            .arg(format!("-DAUTH={auth}"))
            .arg(format!("-DPREHASH={}", u8::from(prehash)))
            .arg(format!("-DVERIFY={}", u8::from(verify)))
            .arg("-I")
            .arg(root.join("headers/3.2"))
            .arg(root.join("hash_ml_dsa.c"))
            .arg("-o")
            .arg(fixture.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fixture
    }
    /// Native module path.
    pub fn path(&self) -> PathBuf {
        self.0.join("module.so")
    }
}
impl Drop for HashMlDsaModule {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
