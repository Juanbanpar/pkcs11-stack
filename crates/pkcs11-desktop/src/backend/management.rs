// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{BackendError, BackendResult, Registry, ResourceId, browse::read_session};
use pkcs11_client::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, Authentication, CertificateDocument,
    EcdhKeyPairRequest, KeyKind, MlDsaParameterSet, MlKemParameterSet, NamedCurve, SessionMode,
    SessionState,
};

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationKind {
    Signing(KeyKind),
    MlDsa(MlDsaParameterSet),
    MlKem(MlKemParameterSet),
    Ecdh(NamedCurve),
    Aes(AesKeySize, AesKeyPurpose),
}
impl GenerationKind {
    pub fn supports_context_authentication(self) -> bool {
        matches!(self, Self::Signing(_) | Self::MlDsa(_))
    }
    pub fn validate(self, id: &[u8], label: &[u8], context: bool) -> Result<(), BackendError> {
        let valid = match self {
            Self::Signing(_) | Self::MlDsa(_) => !id.is_empty() && !label.is_empty(),
            Self::MlKem(_) => !context && !id.is_empty() && !label.is_empty(),
            Self::Ecdh(curve) => {
                !context && EcdhKeyPairRequest { curve, id, label }.validate().is_ok()
            }
            Self::Aes(size, purpose) => {
                !context
                    && AesKeyRequest {
                        size,
                        purpose,
                        id,
                        label,
                    }
                    .validate()
                    .is_ok()
            }
        };
        valid.then_some(()).ok_or(BackendError::InvalidForm)
    }
}
pub enum ManagementAction {
    Generate {
        kind: GenerationKind,
        id: Vec<u8>,
        label: Vec<u8>,
        always_authenticate: bool,
    },
    ImportCertificate {
        path: PathBuf,
        id: Vec<u8>,
        label: Vec<u8>,
    },
    Delete {
        object: ResourceId,
    },
    Export {
        object: ResourceId,
        path: PathBuf,
    },
}
fn certificate(path: &Path) -> Result<CertificateDocument, BackendError> {
    const MAXIMUM: u64 = 16 * 1024 * 1024;
    let file = File::open(path).map_err(|_| BackendError::FileRead)?;
    let mut bytes = Vec::new();
    file.take(MAXIMUM + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BackendError::FileRead)?;
    if bytes.len() as u64 > MAXIMUM {
        return Err(BackendError::FileRead);
    }
    CertificateDocument::from_der(bytes).map_err(|_| BackendError::FileRead)
}
pub(super) fn create_output(path: &Path) -> Result<File, BackendError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|_| BackendError::FileWrite)
}
fn save_new(path: &Path, bytes: &[u8]) -> Result<(), BackendError> {
    let mut file = create_output(path)?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .map_err(|_| BackendError::FileWrite)
}
impl Registry {
    pub(super) fn capabilities(
        &self,
        module: ResourceId,
        token: ResourceId,
    ) -> Result<Vec<GenerationKind>, BackendError> {
        let (index, uri) = self.location(module, token)?;
        let choices = self.modules[index]
            .provider
            .generation_capabilities(&uri)
            .map_err(|e| BackendError::from(&e))?;
        Ok(choices
            .signing
            .into_iter()
            .map(GenerationKind::Signing)
            .chain(choices.ml_dsa.into_iter().map(GenerationKind::MlDsa))
            .chain(choices.ml_kem.into_iter().map(GenerationKind::MlKem))
            .chain(choices.ecdh.into_iter().map(GenerationKind::Ecdh))
            .chain(choices.aes.into_iter().flat_map(|size| {
                [AesKeyPurpose::Encryption, AesKeyPurpose::Wrapping]
                    .map(|purpose| GenerationKind::Aes(size, purpose))
            }))
            .collect())
    }
    fn management_action(
        &mut self,
        module: ResourceId,
        token: ResourceId,
        action: ManagementAction,
    ) -> Result<(), BackendError> {
        let (index, uri) = self.location(module, token)?;
        if let ManagementAction::Export { object, path } = action {
            let (reference, _) = self.reference(module, token, object)?;
            let bytes = read_session(
                &self.modules[index],
                &uri,
                self.modules[index].read_mode(token)?,
                |session| {
                    session.export_public(&reference).map_err(|e| match e {
                        pkcs11_client::Error::UnsupportedExport
                        | pkcs11_client::Error::InvalidPublicKey => BackendError::ExportUnavailable,
                        _ => BackendError::from(&e),
                    })
                },
            )?;
            return save_new(&path, &bytes);
        }
        let entry = self.modules[index]
            .entry
            .tokens
            .iter()
            .find(|entry| entry.id == token)
            .ok_or(BackendError::UnknownToken)?;
        if !entry.can_manage() {
            return Err(BackendError::ManagementUnavailable);
        }
        // Capture a catalog selector before refresh invalidates every object ID.
        let reference = match &action {
            ManagementAction::Delete { object } => Some(self.reference(module, token, *object)?.0),
            _ => None,
        };
        let document = match &action {
            ManagementAction::ImportCertificate { path, .. } => Some(certificate(path)?),
            _ => None,
        };
        if let ManagementAction::Generate { kind, .. } = &action
            && !self.capabilities(module, token)?.contains(kind)
        {
            return Err(BackendError::InvalidForm);
        }
        let mut session = self.modules[index]
            .provider
            .management(&uri, SessionMode::ReadWrite, Authentication::None)
            .map_err(|e| BackendError::from(&e))?;
        let result = (|| {
            if session.state().map_err(|e| BackendError::from(&e))? != SessionState::RwUser {
                return Err(BackendError::ManagementUnavailable);
            }
            match action {
                ManagementAction::Generate {
                    kind,
                    id,
                    label,
                    always_authenticate,
                } => {
                    kind.validate(&id, &label, always_authenticate)?;
                    match kind {
                        GenerationKind::Signing(kind) => session.generate_signing_key_pair(
                            kind,
                            &id,
                            &label,
                            always_authenticate,
                        ),
                        GenerationKind::MlDsa(parameter) => session.generate_ml_dsa_key_pair(
                            parameter,
                            &id,
                            &label,
                            always_authenticate,
                        ),
                        GenerationKind::MlKem(parameter) => {
                            session.generate_ml_kem_key_pair(parameter, &id, &label)
                        }
                        GenerationKind::Ecdh(curve) => {
                            session.generate_ecdh_key_pair(&EcdhKeyPairRequest {
                                curve,
                                id: &id,
                                label: &label,
                            })
                        }
                        GenerationKind::Aes(size, purpose) => {
                            session.generate_aes_key(&AesKeyRequest {
                                size,
                                purpose,
                                id: &id,
                                label: &label,
                            })
                        }
                    }
                }
                ManagementAction::ImportCertificate { id, label, .. } => {
                    if id.is_empty() || label.is_empty() {
                        return Err(BackendError::InvalidForm);
                    }
                    session.import_certificate(
                        document.as_ref().expect("parsed certificate"),
                        &id,
                        &label,
                    )
                }
                ManagementAction::Delete { .. } => {
                    session.delete(reference.as_ref().expect("resolved selector"))
                }
                ManagementAction::Export { .. } => unreachable!(),
            }
            .map_err(|e| BackendError::from(&e))
        })();
        let closed = session.close().map_err(|e| BackendError::from(&e));
        super::finish_session(result, closed, &self.modules[index].cleanup_failed)
    }
    pub(super) fn manage(
        &mut self,
        module: ResourceId,
        token: ResourceId,
        action: ManagementAction,
    ) -> BackendResult {
        let operation = self.management_action(module, token, action);
        // Even a failed mutation can have effects. Invalidate and rediscover once, never retry it.
        let refreshed = self
            .modules
            .iter()
            .position(|entry| entry.entry.id == module)
            .ok_or(BackendError::UnknownModule)
            .and_then(|index| self.discover(index));
        let objects = refreshed.and_then(|()| self.objects(module, token));
        let error = operation.err().or_else(|| {
            objects
                .is_err()
                .then_some(BackendError::RefreshAfterManagement)
        });
        BackendResult::Managed {
            module,
            token,
            modules: self
                .modules
                .iter()
                .map(|entry| entry.entry.clone())
                .collect(),
            objects: objects.ok(),
            error,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_certificate_and_existing_export_file_are_fixed_errors() {
        let directory =
            std::env::temp_dir().join(format!("pkcs11-desktop-file-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("public.bin");
        save_new(&path, b"original").unwrap();
        assert_eq!(
            save_new(&path, b"replacement"),
            Err(BackendError::FileWrite)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        assert!(matches!(certificate(&path), Err(BackendError::FileRead)));
        let oversized = directory.join("oversized.der");
        File::create(&oversized)
            .unwrap()
            .set_len(16 * 1024 * 1024 + 1)
            .unwrap();
        assert!(matches!(
            certificate(&oversized),
            Err(BackendError::FileRead)
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::backend::{BackendCommand, BackendEvent, LoginRole, RequestId, SecretInput};
    use pkcs11_client::ObjectClass;
    fn inventory(result: BackendEvent) -> Vec<super::super::ModuleEntry> {
        match result {
            BackendEvent::Completed {
                result:
                    Ok(BackendResult::Modules {
                        modules,
                        error: None,
                        ..
                    }),
                ..
            } => modules,
            event => panic!("unexpected inventory: {event:?}"),
        }
    }
    fn objects(
        result: BackendResult,
        expected_error: Option<BackendError>,
    ) -> Vec<super::super::ObjectEntry> {
        match result {
            BackendResult::Managed {
                objects: Some(objects),
                error,
                ..
            } => {
                assert_eq!(error, expected_error);
                objects
            }
            result => panic!("unexpected management result: {result:?}"),
        }
    }
    fn object_id(
        objects: &[super::super::ObjectEntry],
        label: &str,
        class: ObjectClass,
    ) -> ResourceId {
        objects
            .iter()
            .find(|entry| entry.label == label && entry.class == Some(class))
            .unwrap()
            .id
    }
    #[test]
    #[ignore = "requires the isolated SoftHSM runner"]
    fn software_token_management_generation_import_export_delete_and_failures() {
        assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
        let directory = std::env::temp_dir().join(format!(
            "pkcs11-desktop-management-test-{}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = PathBuf::from(std::env::var_os("PKCS11_TEST_MODULE").unwrap());
        let mut registry = Registry::default();
        let module = registry.load(&path).unwrap();
        let candidates: Vec<_> = registry.modules[0]
            .entry
            .tokens
            .iter()
            .filter(|entry| entry.label == "runtime-test")
            .map(|entry| entry.id)
            .collect();
        let token = candidates
            .into_iter()
            .find(|&token| {
                registry
                    .objects(module, token)
                    .unwrap()
                    .iter()
                    .any(|entry| entry.label == "unique")
            })
            .expect("public fixture token");
        let choices = registry.capabilities(module, token).unwrap();
        assert!(choices.contains(&GenerationKind::Signing(KeyKind::Rsa { bits: 2048 })));
        assert!(choices.contains(&GenerationKind::Signing(KeyKind::Ec(
            pkcs11_client::NamedCurve::P256
        ))));
        let generation = |kind| ManagementAction::Generate {
            kind: GenerationKind::Signing(kind),
            id: vec![0xEE],
            label: b"desktop-key".to_vec(),
            always_authenticate: false,
        };
        objects(
            registry.manage(module, token, generation(KeyKind::Rsa { bits: 2048 })),
            Some(BackendError::ManagementUnavailable),
        );
        inventory(registry.execute(BackendCommand::Login {
            id: RequestId(1),
            module,
            token,
            role: LoginRole::User,
            pin: SecretInput::Value("12345678".into()),
        }));
        let listed = registry.objects(module, token).unwrap();
        let private_data = object_id(&listed, "private", ObjectClass::DATA);
        let denied_data = directory.join("private-data.bin");
        let listed = objects(
            registry.manage(
                module,
                token,
                ManagementAction::Export {
                    object: private_data,
                    path: denied_data.clone(),
                },
            ),
            Some(BackendError::ExportUnavailable),
        );
        assert!(!denied_data.exists());
        let duplicate = object_id(&listed, "duplicate", ObjectClass::DATA);
        let listed = objects(
            registry.manage(
                module,
                token,
                ManagementAction::Delete { object: duplicate },
            ),
            Some(BackendError::AmbiguousObject),
        );
        assert_eq!(
            listed
                .iter()
                .filter(|entry| entry.label == "duplicate")
                .count(),
            2
        );
        for kind in [
            KeyKind::Rsa { bits: 2048 },
            KeyKind::Ec(pkcs11_client::NamedCurve::P256),
        ] {
            let listed = objects(registry.manage(module, token, generation(kind)), None);
            let private = object_id(&listed, "desktop-key", ObjectClass::PRIVATE_KEY);
            let fields = registry.inspect(module, token, private).unwrap().fields;
            assert!(
                fields.iter().any(
                    |field| field.name == "Sensitive" && field.value.as_deref() == Some("true")
                )
            );
            assert!(fields.iter().any(
                |field| field.name == "Extractable" && field.value.as_deref() == Some("false")
            ));
            let denied = directory.join("private.der");
            let listed = objects(
                registry.manage(
                    module,
                    token,
                    ManagementAction::Export {
                        object: private,
                        path: denied.clone(),
                    },
                ),
                Some(BackendError::ExportUnavailable),
            );
            assert!(!denied.exists());
            let public = object_id(&listed, "desktop-key", ObjectClass::PUBLIC_KEY);
            let output = directory.join(format!("{kind:?}.der"));
            let listed = objects(
                registry.manage(
                    module,
                    token,
                    ManagementAction::Export {
                        object: public,
                        path: output.clone(),
                    },
                ),
                None,
            );
            let verified = std::process::Command::new("openssl")
                .args(["pkey", "-pubin", "-inform", "DER", "-in"])
                .arg(&output)
                .args(["-noout", "-text"])
                .output()
                .unwrap();
            assert!(verified.status.success());
            let public = object_id(&listed, "desktop-key", ObjectClass::PUBLIC_KEY);
            let original = std::fs::read(&output).unwrap();
            objects(
                registry.manage(
                    module,
                    token,
                    ManagementAction::Export {
                        object: public,
                        path: output.clone(),
                    },
                ),
                Some(BackendError::FileWrite),
            );
            assert_eq!(std::fs::read(&output).unwrap(), original);
            // Previous catalog IDs cannot delete an object after a management refresh.
            let listed = objects(
                registry.manage(module, token, ManagementAction::Delete { object: public }),
                Some(BackendError::UnknownObject),
            );
            let public = object_id(&listed, "desktop-key", ObjectClass::PUBLIC_KEY);
            let listed = objects(
                registry.manage(module, token, ManagementAction::Delete { object: public }),
                None,
            );
            let private = object_id(&listed, "desktop-key", ObjectClass::PRIVATE_KEY);
            let listed = objects(
                registry.manage(module, token, ManagementAction::Delete { object: private }),
                None,
            );
            assert!(listed.iter().all(|entry| entry.label != "desktop-key"));
        }
        let certificate_path = directory.join("fixture.der");
        let certificate_bytes = include_bytes!("../../../pkcs11-client/tests/fixtures/ed25519.der");
        std::fs::write(&certificate_path, certificate_bytes).unwrap();
        let listed = objects(
            registry.manage(
                module,
                token,
                ManagementAction::ImportCertificate {
                    path: certificate_path,
                    id: vec![0xDD],
                    label: b"desktop-certificate".to_vec(),
                },
            ),
            None,
        );
        let certificate_id = object_id(&listed, "desktop-certificate", ObjectClass::CERTIFICATE);
        let exported = directory.join("certificate.der");
        let listed = objects(
            registry.manage(
                module,
                token,
                ManagementAction::Export {
                    object: certificate_id,
                    path: exported.clone(),
                },
            ),
            None,
        );
        assert_eq!(std::fs::read(exported).unwrap(), certificate_bytes);
        let certificate_id = object_id(&listed, "desktop-certificate", ObjectClass::CERTIFICATE);
        objects(
            registry.manage(
                module,
                token,
                ManagementAction::Delete {
                    object: certificate_id,
                },
            ),
            None,
        );
        // Invalid parsing cannot mutate the token, but still invalidates cached IDs.
        let invalid = directory.join("invalid.der");
        std::fs::write(&invalid, b"not-a-certificate-canary").unwrap();
        let listed = objects(
            registry.manage(
                module,
                token,
                ManagementAction::ImportCertificate {
                    path: invalid,
                    id: vec![0xDD],
                    label: b"must-not-exist".to_vec(),
                },
            ),
            Some(BackendError::FileRead),
        );
        assert!(listed.iter().all(|entry| entry.label != "must-not-exist"));
        assert!(!format!("{listed:?}").contains("not-a-certificate-canary"));
        registry.close().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}
