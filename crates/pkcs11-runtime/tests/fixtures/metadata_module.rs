// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared native metadata fixture for runtime and application-boundary tests.
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

/// Disposable module compiled against independent OASIS 3.2 headers.
pub struct MetadataModule {
    dir: PathBuf,
    path: PathBuf,
}
impl MetadataModule {
    /// Select opaque scalar patterns (0–2), malformed lengths (3–14), or a native error (15).
    pub fn new(fault: u8) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pkcs11-opaque-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let fixture = Self {
            path: dir.join("fixture.so"),
            dir,
        };
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkcs11-runtime/tests/fixtures");
        let result = Command::new("cc")
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
            .arg(format!("-DFAULT={fault}"))
            .arg("-I")
            .arg(root.join("headers/3.2"))
            .arg(root.join("opaque_metadata.c"))
            .arg("-o")
            .arg(fixture.path())
            .output()
            .expect("C compiler for the native metadata fixture");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        fixture
    }
    /// Path to the trusted, locally compiled test module.
    pub fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for MetadataModule {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}
