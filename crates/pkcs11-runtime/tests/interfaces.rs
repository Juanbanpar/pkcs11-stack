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
        Self::from_source("interface.c", version, fault, interface_only)
    }
    fn from_source(source: &str, version: V, fault: u8, interface_only: bool) -> Self {
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
            .arg(root.join(source))
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

#[test]
fn digest_entry_points_flags_bounded_outputs_and_failures() {
    use pkcs11_runtime::{DigestMode, Error, HashAlgorithm, SessionMode};
    for fault in 0..=8 {
        let fixture = Fixture::from_source("digest.c", V::V2_40, fault, false);
        let module = fixture.load(InterfaceSelection::Auto).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=digest".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        if fault == 1 || fault == 2 {
            assert!(
                token
                    .digest_algorithms(DigestMode::Multipart)
                    .unwrap()
                    .is_empty()
            );
            assert!(matches!(
                session.start_digest(HashAlgorithm::Sha256),
                Err(Error::UnsupportedDigest)
            ));
            session.info().unwrap();
            if fault == 2 {
                assert_eq!(
                    session.digest(HashAlgorithm::Sha256, b"abc").unwrap(),
                    [0xAB; 32]
                );
            }
        } else if fault == 0 {
            assert_eq!(
                session.digest(HashAlgorithm::Sha256, b"abc").unwrap(),
                [0xAB; 32]
            );
            let mut operation = session.start_digest(HashAlgorithm::Sha256).unwrap();
            operation.update(b"").unwrap();
            operation.update(b"abc").unwrap();
            assert_eq!(operation.finish().unwrap(), [0xAB; 32]);
            session.info().unwrap();
            drop(session.start_digest(HashAlgorithm::Sha256).unwrap());
            assert!(matches!(session.info(), Err(Error::Closed)));
        } else if fault == 3 {
            assert!(session.start_digest(HashAlgorithm::Sha256).is_err());
            assert!(matches!(session.info(), Err(Error::Closed)));
        } else {
            let mut operation = session.start_digest(HashAlgorithm::Sha256).unwrap();
            if fault == 4 {
                assert!(operation.update(b"abc").is_err());
                assert!(matches!(operation.update(b"abc"), Err(Error::Closed)));
                assert!(matches!(operation.finish(), Err(Error::Closed)));
            } else {
                operation.update(b"abc").unwrap();
                assert!(operation.finish().is_err());
            }
            assert!(matches!(session.info(), Err(Error::Closed)));
        }
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}

#[test]
fn cmac_permissions_pointers_bounded_outputs_and_verification_failures() {
    use pkcs11_runtime::{Error, MacOperation, ObjectRef, SessionMode};
    for fault in 0..=15 {
        let fixture = Fixture::from_source("cmac.c", V::V2_40, fault, false);
        let module = fixture.load(InterfaceSelection::Auto).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let key =
            ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap();
        for operation in [MacOperation::Generate, MacOperation::Verify] {
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let unsupported = match operation {
                MacOperation::Generate => [1, 2, 12, 14].contains(&fault),
                MacOperation::Verify => [10, 11, 13, 15].contains(&fault),
            };
            if unsupported {
                assert!(matches!(
                    session.aes_cmac_capabilities(&key, operation),
                    Err(Error::UnsupportedMac)
                ));
                session.info().unwrap();
            } else if operation == MacOperation::Generate {
                let result = session.mac_aes_cmac(&key, b"message");
                if [3, 4, 5, 6, 7].contains(&fault) {
                    assert!(result.is_err());
                    assert!(matches!(session.info(), Err(Error::Closed)));
                } else {
                    assert_eq!(result.unwrap(), [0xAB; 16]);
                    session.info().unwrap();
                }
            } else if [3, 8, 9].contains(&fault) {
                assert!(
                    session
                        .verify_aes_cmac(&key, b"message", &[0xAB; 16])
                        .is_err()
                );
                assert!(matches!(session.info(), Err(Error::Closed)));
            } else {
                for tag in [&[][..], &[0; 16][..], &[0; 17][..]] {
                    assert!(matches!(
                        session.verify_aes_cmac(&key, b"message", tag),
                        Err(Error::MacMismatch)
                    ));
                    session.info().unwrap();
                }
                session
                    .verify_aes_cmac(&key, b"message", &[0xAB; 16])
                    .unwrap();
                session.info().unwrap();
            }
            session.close().unwrap();
        }
        drop(token);
        module.finalize().unwrap();
    }
}

#[test]
fn hmac_permissions_pointers_bounded_outputs_and_verification_failures() {
    use pkcs11_runtime::{Error, HmacAlgorithm, MacOperation, ObjectRef, SessionMode};
    for fault in 0..=15 {
        let fixture = Fixture::from_source("hmac.c", V::V2_40, fault, false);
        let module = fixture.load(InterfaceSelection::Auto).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let key =
            ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap();
        for operation in [MacOperation::Generate, MacOperation::Verify] {
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let unsupported = match operation {
                MacOperation::Generate => [1, 2, 12, 14].contains(&fault),
                MacOperation::Verify => [10, 11, 13, 15].contains(&fault),
            };
            if unsupported {
                assert!(matches!(
                    session.hmac_capabilities(&key, operation),
                    Err(Error::UnsupportedMac)
                ));
                session.info().unwrap();
            } else if operation == MacOperation::Generate {
                let result = session.mac_hmac(&key, HmacAlgorithm::Sha384, b"message");
                if [3, 4, 5, 6, 7].contains(&fault) {
                    assert!(result.is_err());
                    assert!(matches!(session.info(), Err(Error::Closed)));
                } else {
                    assert_eq!(result.unwrap(), [0xAB; 48]);
                    session.info().unwrap();
                }
            } else if [3, 8, 9].contains(&fault) {
                assert!(
                    session
                        .verify_hmac(&key, HmacAlgorithm::Sha384, b"message", &[0xAB; 48])
                        .is_err()
                );
                assert!(matches!(session.info(), Err(Error::Closed)));
            } else {
                for tag in [&[][..], &[0; 48][..], &[0; 49][..]] {
                    assert!(matches!(
                        session.verify_hmac(&key, HmacAlgorithm::Sha384, b"message", tag),
                        Err(Error::MacMismatch)
                    ));
                    session.info().unwrap();
                }
                session
                    .verify_hmac(&key, HmacAlgorithm::Sha384, b"message", &[0xAB; 48])
                    .unwrap();
                session.info().unwrap();
            }
            session.close().unwrap();
        }
        drop(token);
        module.finalize().unwrap();
    }
}

#[test]
fn full_hmac_profiles_pass_native_ids_parameter_shape_and_exact_output_lengths() {
    use pkcs11_runtime::{HmacAlgorithm, MacOperation, ObjectRef, SessionMode};
    for (index, algorithm) in HmacAlgorithm::ALL.into_iter().enumerate() {
        let fixture = Fixture::from_source("hmac_profiles.c", V::V3_2, index as u8, false);
        let module = fixture.load(InterfaceSelection::Auto).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let key =
            ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let expected = vec![0xAB; algorithm.tag_length()];
        for direction in [MacOperation::Generate, MacOperation::Verify] {
            let caps = session.hmac_capabilities(&key, direction).unwrap();
            for candidate in HmacAlgorithm::ALL {
                assert_eq!(caps.supports(candidate), candidate == algorithm);
            }
        }
        assert_eq!(
            session
                .mac_hmac(&key, algorithm, b"native profile")
                .unwrap(),
            expected
        );
        session
            .verify_hmac(&key, algorithm, b"native profile", &expected)
            .unwrap();
        session.info().unwrap();
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
