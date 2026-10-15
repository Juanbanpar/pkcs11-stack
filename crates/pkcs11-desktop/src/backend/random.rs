// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{BackendError, Registry, ResourceId, browse::read_session};
use pkcs11_client::RandomRequest;
use secrecy::ExposeSecret;
use std::{io::Write, path::Path};

impl Registry {
    pub(super) fn random_file(
        &self,
        module: ResourceId,
        token: ResourceId,
        request: RandomRequest,
        path: &Path,
    ) -> Result<(), BackendError> {
        let (index, uri) = self.location(module, token)?;
        let module = &self.modules[index];
        if !module
            .entry
            .tokens
            .iter()
            .any(|entry| entry.id == token && entry.can_random())
        {
            return Err(BackendError::RandomUnavailable);
        }
        // Reserve the path before requesting bytes. Existing files never trigger generation.
        let mut output = super::management::create_output(path)?;
        let bytes = read_session(module, &uri, module.read_mode(token)?, |session| {
            session
                .generate_random(request)
                .map_err(|error| BackendError::from(&error))
        })?;
        output
            .write_all(bytes.expose_secret())
            .and_then(|()| output.flush())
            .map_err(|_| BackendError::FileWrite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{
        BackendCommand, BackendEvent, BackendResult, LoginRole, RequestId, SecretInput,
    };
    #[test]
    fn unknown_random_target_never_creates_output() {
        let mut registry = Registry::default();
        let path =
            std::env::temp_dir().join(format!("desktop-unknown-random-{}", std::process::id()));
        let event = registry.execute(BackendCommand::Random {
            id: RequestId(1),
            module: ResourceId(1),
            token: ResourceId(2),
            request: RandomRequest::new(32).unwrap(),
            path: path.clone(),
        });
        assert!(matches!(
            event,
            BackendEvent::Completed {
                id: RequestId(1),
                result: Err(BackendError::UnknownModule)
            }
        ));
        assert!(!path.exists());
    }
    #[test]
    #[ignore = "requires the isolated SoftHSM runner"]
    fn software_token_random_files_roles_capabilities_and_shutdown() {
        assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
        let directory =
            std::env::temp_dir().join(format!("desktop-random-test-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_MODULE").unwrap());
        let mut registry = Registry::default();
        let module = registry.load(&path).unwrap();
        let token = registry.modules[0]
            .entry
            .tokens
            .iter()
            .find(|entry| entry.label == "client-test")
            .unwrap()
            .id;
        let index = registry.modules[0]
            .entry
            .tokens
            .iter()
            .position(|entry| entry.id == token)
            .unwrap();
        assert!(registry.modules[0].entry.tokens[index].can_random());
        registry.modules[0].entry.tokens[index].rng = false;
        let unavailable = directory.join("unavailable");
        assert_eq!(
            registry.random_file(module, token, RandomRequest::new(32).unwrap(), &unavailable),
            Err(BackendError::RandomUnavailable)
        );
        assert!(!unavailable.exists());
        registry.modules[0].entry.tokens[index].rng = true;
        for (number, role) in [
            None,
            Some(LoginRole::User),
            Some(LoginRole::SecurityOfficer),
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(role) = role {
                let pin = if role == LoginRole::User {
                    "12345678"
                } else {
                    "87654321"
                };
                let event = registry.execute(BackendCommand::Login {
                    id: RequestId(1),
                    module,
                    token,
                    role,
                    pin: SecretInput::Value(pin.into()),
                });
                assert!(matches!(
                    event,
                    BackendEvent::Completed {
                        result: Ok(BackendResult::Modules { error: None, .. }),
                        ..
                    }
                ));
            }
            let output = directory.join(format!("random-{number}"));
            let event = registry.execute(BackendCommand::Random {
                id: RequestId(2),
                module,
                token,
                request: RandomRequest::new(1024).unwrap(),
                path: output.clone(),
            });
            assert!(matches!(
                event,
                BackendEvent::Completed {
                    id: RequestId(2),
                    result: Ok(BackendResult::RandomWritten { length: 1024 })
                }
            ));
            let saved = std::fs::read(&output).unwrap();
            assert_eq!(saved.len(), 1024);
            assert!(!format!("{event:?}").contains(&format!("{saved:?}")));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            assert_eq!(
                registry.random_file(module, token, RandomRequest::new(32).unwrap(), &output),
                Err(BackendError::FileWrite)
            );
            assert_eq!(std::fs::read(&output).unwrap(), saved);
            if role.is_some() {
                registry.logout(module, token).unwrap();
            }
        }
        registry.close().unwrap();
        let provider = pkcs11_client::Provider::load(&path).unwrap();
        provider.finalize().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}
