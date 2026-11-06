// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure SLH-DSA native ABI, bounds and authentication fixture.
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

/// Locally compiled fixture; does not access operator token stores.
pub struct SlhDsaModule(PathBuf);
impl SlhDsaModule {
    /// Compile the exact table layout and selected failure path.
    pub fn new(
        table: (u8, u8),
        parameter: usize,
        fault: usize,
        auth: bool,
        hedge: usize,
        context_length: usize,
    ) -> Self {
        let (major, minor) = table;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pkcs11-slh-{}-{}",
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
            .arg(format!("-DAUTH={}", u8::from(auth)))
            .arg(format!("-DHEDGE={hedge}"))
            .arg(format!("-DCONTEXT_LENGTH={context_length}"))
            .arg("-I")
            .arg(root.join("headers/3.2"))
            .arg(root.join("slh_dsa.c"))
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
impl Drop for SlhDsaModule {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
