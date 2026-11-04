// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disposable KBKDF module compiled with the requested official headers.
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

/// Locally compiled fixture; does not access operator token stores.
pub struct KbkdfCmacModule(PathBuf);
impl KbkdfCmacModule {
    /// Compile the exact table layout and selected failure path.
    #[allow(dead_code)]
    pub fn new(major: u8, minor: u8, fault: u8, key_length: usize) -> Self {
        Self::build(major, minor, fault, key_length, None)
    }
    /// Select independent native HMAC identifiers, with a 31-byte base key.
    #[allow(dead_code)]
    pub fn hmac(
        major: u8,
        minor: u8,
        fault: u8,
        mechanism: &str,
        key_type: &str,
        block_length: usize,
    ) -> Self {
        Self::build(
            major,
            minor,
            fault,
            31,
            Some((mechanism, key_type, block_length)),
        )
    }
    fn build(
        major: u8,
        minor: u8,
        fault: u8,
        key_length: usize,
        hmac: Option<(&str, &str, usize)>,
    ) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pkcs11-kbkdf-cmac-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let fixture = Self(dir);
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkcs11-runtime/tests/fixtures");
        let mut command = Command::new("cc");
        if let Some((mechanism, key_type, block_length)) = hmac {
            command
                .arg(format!("-DKDF_PRF={mechanism}"))
                .arg(format!("-DKDF_KEY_TYPE={key_type}"))
                .arg(format!("-DKDF_BLOCK_LENGTH={block_length}"));
        }
        let output = command
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
            .arg(format!("-DKDF_BASE_LENGTH={key_length}"))
            .arg("-I")
            .arg(root.join("headers").join(format!("{major}.{minor}")))
            .arg(root.join("kbkdf_cmac.c"))
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
impl Drop for KbkdfCmacModule {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
