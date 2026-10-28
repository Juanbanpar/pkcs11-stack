// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disposable multipart MAC module compiled with the requested official headers.
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

/// Locally compiled fixture; does not access operator token stores.
pub struct MacStreamModule(PathBuf);
impl MacStreamModule {
    /// Compile the exact table layout and selected failure path.
    pub fn new(major: u8, minor: u8, fault: u8, hmac: bool, general: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pkcs11-mac-stream-{}-{}",
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
            .arg(format!("-DHMAC={}", u8::from(hmac)))
            .arg(format!("-DGENERAL={}", u8::from(general)))
            .arg("-I")
            .arg(root.join("headers").join(format!("{major}.{minor}")))
            .arg(root.join("mac_stream.c"))
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
impl Drop for MacStreamModule {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
