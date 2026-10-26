// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native ABI fixtures use official headers, independently of Rust's bindings.
#![cfg(unix)]
use pkcs11_runtime::{Function, InterfaceSelection, InterfaceVersion as V, Module, ModuleOptions};
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new(version: V, fault: u8, interface_only: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pkcs11-interface-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).expect("fresh fixture directory");
        let fixture = Self(dir);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let mut compiler = Command::new("cc");
        compiler.args(["-std=c99", "-Wall", "-Wextra", "-Werror", "-fPIC"]);
        compiler.arg(if cfg!(target_os = "macos") {
            "-dynamiclib"
        } else {
            "-shared"
        });
        compiler.arg(format!("-DAPI_MAJOR={}", version.major()));
        compiler.arg(format!("-DAPI_MINOR={}", version.minor()));
        compiler.arg(format!("-DFAULT={fault}"));
        if interface_only {
            compiler.arg("-DINTERFACE_ONLY");
        }
        compiler
            .arg("-I")
            .arg(root.join("headers").join(version.to_string()));
        let result = compiler
            .arg(root.join("interface.c"))
            .arg("-o")
            .arg(fixture.path())
            .output()
            .expect("C compiler for native PKCS#11 ABI fixtures");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        fixture
    }
    fn path(&self) -> PathBuf {
        self.0.join("fixture.so")
    }
    fn load(&self, interface: InterfaceSelection) -> Result<Module, pkcs11_runtime::Error> {
        Module::load_with_options(self.path(), ModuleOptions { interface })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn negotiates_all_supported_layouts_and_exact_versions() {
    for version in [V::V2_40, V::V3_0, V::V3_1, V::V3_2] {
        let fixture = Fixture::new(version, 0, false);
        for selection in [InterfaceSelection::Auto, InterfaceSelection::Exact(version)] {
            let module = fixture.load(selection).unwrap();
            assert_eq!(module.interface().version, version);
            assert_eq!(module.interface().legacy, version == V::V2_40);
            assert_eq!(module.interface().flags != 0, version != V::V2_40);
            assert_eq!(
                module.supports_function(Function::SessionCancel),
                version != V::V2_40
            );
            assert_eq!(
                module.supports_function(Function::EncapsulateKey),
                version == V::V3_2
            );
            assert!(module.slots(false).unwrap().is_empty());
            module.finalize().unwrap();
        }
        let module = fixture.load(InterfaceSelection::Exact(V::V2_40)).unwrap();
        assert_eq!(module.interface().version, V::V2_40);
        module.finalize().unwrap();
        if version != V::V3_2 {
            assert!(fixture.load(InterfaceSelection::Exact(V::V3_2)).is_err());
        }
    }
}

#[test]
fn unavailable_interfaces_fall_back_only_in_automatic_mode() {
    for fault in [10, 11] {
        let fixture = Fixture::new(V::V3_2, fault, false);
        let module = fixture.load(InterfaceSelection::Auto).unwrap();
        assert_eq!(module.interface().version, V::V2_40);
        module.finalize().unwrap();
        assert!(fixture.load(InterfaceSelection::Exact(V::V3_2)).is_err());
    }
    let fixture = Fixture::new(V::V3_2, 0, true);
    let module = fixture.load(InterfaceSelection::Auto).unwrap();
    assert_eq!(module.interface().version, V::V3_2);
    module.finalize().unwrap();
    assert!(fixture.load(InterfaceSelection::Exact(V::V2_40)).is_err());
}

#[test]
fn malformed_interfaces_and_provider_failures_are_not_downgraded() {
    for fault in [1, 2, 3, 4, 5, 6, 9, 13, 14, 15] {
        let fixture = Fixture::new(V::V3_2, fault, false);
        for selection in [InterfaceSelection::Auto, InterfaceSelection::Exact(V::V3_2)] {
            assert!(fixture.load(selection).is_err(), "accepted fault {fault}");
        }
    }
    for fault in [7, 8, 9, 14, 15] {
        let fixture = Fixture::new(V::V2_40, fault, false);
        assert!(
            fixture.load(InterfaceSelection::Auto).is_err(),
            "accepted legacy fault {fault}"
        );
    }
}

#[test]
fn automatic_selection_prefers_highest_available_and_exact_selection_is_honored() {
    let fixture = Fixture::new(V::V3_2, 16, false);
    let module = fixture.load(InterfaceSelection::Auto).unwrap();
    assert_eq!(module.interface().version, V::V3_2);
    module.finalize().unwrap();
    for version in [V::V3_0, V::V3_1] {
        let module = fixture.load(InterfaceSelection::Exact(version)).unwrap();
        assert_eq!(module.interface().version, version);
        assert!(!module.supports_function(Function::EncapsulateKey));
        assert_eq!(module.info().cryptoki_version().minor(), 2);
        module.finalize().unwrap();
    }
}

#[test]
fn legacy_entry_point_never_exposes_newer_functions_despite_known_version_field() {
    let fixture = Fixture::new(V::V3_2, 17, false);
    let module = fixture.load(InterfaceSelection::Exact(V::V2_40)).unwrap();
    assert_eq!(module.interface().version, V::V2_40);
    assert_eq!(module.interface().reported_version.major(), 3);
    assert_eq!(module.interface().reported_version.minor(), 2);
    assert!(!module.supports_function(Function::SessionCancel));
    assert!(!module.supports_function(Function::EncapsulateKey));
    module.finalize().unwrap();
}
