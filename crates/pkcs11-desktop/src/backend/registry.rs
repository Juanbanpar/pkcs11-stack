// SPDX-License-Identifier: MIT OR Apache-2.0
use std::path::Path;

use pkcs11_client::Provider;

#[cfg(test)]
use super::SyntheticOutcome;
use super::{
    BackendCommand, BackendError, BackendEvent, BackendResult, LoginState, ModuleEntry, ResourceId,
    SlotEntry, TokenEntry, browse,
};

pub(super) fn finish_session<T>(
    result: Result<T, BackendError>,
    closed: Result<(), BackendError>,
    cleanup_failed: &std::cell::Cell<bool>,
) -> Result<T, BackendError> {
    if closed.is_err() {
        cleanup_failed.set(true);
        return Err(BackendError::SessionCleanup);
    }
    result
}

pub(super) struct LoadedModule {
    pub(super) cleanup_failed: std::cell::Cell<bool>,
    pub(super) provider: Provider,
    pub(super) entry: ModuleEntry,
    pub(super) catalogs: Vec<browse::ObjectCatalog>,
    pub(super) authentication: Vec<(ResourceId, pkcs11_client::ManagementSession<'static>)>,
}
#[derive(Default)]
pub(super) struct Registry {
    pub(super) modules: Vec<LoadedModule>,
    pub(super) next_resource: u64,
}
impl Registry {
    pub(super) fn allocate(&mut self) -> Result<ResourceId, BackendError> {
        self.next_resource = self
            .next_resource
            .checked_add(1)
            .ok_or(BackendError::ResourceExhausted)?;
        Ok(ResourceId(self.next_resource))
    }

    pub(super) fn discover(&mut self, index: usize) -> Result<(), BackendError> {
        self.modules[index].catalogs.clear();
        let result = if self.modules[index].cleanup_failed.get() {
            Err(BackendError::SessionCleanup)
        } else {
            self.discover_inner(index)
        };
        let cleanup = if result.is_err() {
            self.modules[index].close_authentication()
        } else {
            Ok(())
        };
        let result = cleanup.and(result);
        if let Err(error) = result {
            let entry = &mut self.modules[index].entry;
            entry.slots.clear();
            entry.tokens.clear();
            entry.discovery_error = Some(error);
        }
        result
    }

    fn discover_inner(&mut self, index: usize) -> Result<(), BackendError> {
        // Discovery uses provider metadata; authentication sessions stay worker-local.
        let result = (|| {
            let provider = &self.modules[index].provider;
            let slots = provider.slots(false).map_err(|e| BackendError::from(&e))?;
            let tokens = provider.tokens().map_err(|e| BackendError::from(&e))?;
            Ok::<_, BackendError>((slots, tokens))
        })();
        let (slots, tokens) = result?;
        let mut entries = Vec::new();
        for token in tokens {
            let info = &token.info;
            let mut entry = TokenEntry {
                initialization: token.initialization_target(),
                id: ResourceId(0),
                slot_id: token.slot_id,
                label: info.label().into(),
                manufacturer: info.manufacturer_id().into(),
                model: info.model().into(),
                serial: info.serial_number().into(),
                uri: token.uri().ok().map(|uri| uri.to_string()),
                login: LoginState::Public,
                initialized: info.token_initialized(),
                user_pin_initialized: info.user_pin_initialized(),
                user_pin_locked: info.user_pin_locked(),
                so_pin_locked: info.so_pin_locked(),
                write_protected: info.write_protected(),
                protected_path: info.protected_authentication_path(),
                rng: info.rng(),
                details: vec![
                    ("Initialized".into(), info.token_initialized().to_string()),
                    ("Login required".into(), info.login_required().to_string()),
                    (
                        "USER PIN initialized".into(),
                        info.user_pin_initialized().to_string(),
                    ),
                    ("USER PIN locked".into(), info.user_pin_locked().to_string()),
                    (
                        "Protected authentication path".into(),
                        info.protected_authentication_path().to_string(),
                    ),
                    ("Write protected".into(), info.write_protected().to_string()),
                    ("Random generator".into(), info.rng().to_string()),
                    (
                        "Hardware version".into(),
                        info.hardware_version().to_string(),
                    ),
                    (
                        "Firmware version".into(),
                        info.firmware_version().to_string(),
                    ),
                    (
                        "PIN length".into(),
                        format!("{}–{} bytes", info.min_pin_length(), info.max_pin_length()),
                    ),
                ],
            };
            entry.id = match self.modules[index]
                .entry
                .tokens
                .iter()
                .find(|old| old.same_resource(&entry))
            {
                Some(old) => old.id,
                None => self.allocate()?,
            };
            entries.push(entry);
        }
        let entry = &mut self.modules[index].entry;
        entry.slots = slots
            .into_iter()
            .map(|slot| SlotEntry {
                id: slot.id,
                description: slot.info.slot_description().into(),
                manufacturer: slot.info.manufacturer_id().into(),
                token_present: slot.info.token_present(),
            })
            .collect();
        entry.tokens = entries;
        entry.discovery_error = None;
        self.modules[index].refresh_authentication()
    }

    pub(super) fn load(&mut self, path: &Path) -> Result<ResourceId, BackendError> {
        let path = path.canonicalize().map_err(|_| BackendError::ModulePath)?;
        if self.modules.iter().any(|m| m.entry.path == path) {
            return Err(BackendError::AlreadyLoaded);
        }
        let id = self.allocate()?;
        let provider = Provider::load(&path).map_err(|e| BackendError::from(&e))?;
        let info = provider.info();
        let entry = ModuleEntry {
            id,
            path,
            description: info.library_description().into(),
            manufacturer: info.manufacturer_id().into(),
            library_version: info.library_version().to_string(),
            cryptoki_version: info.cryptoki_version().to_string(),
            slots: Vec::new(),
            tokens: Vec::new(),
            discovery_error: None,
        };
        self.modules.push(LoadedModule {
            cleanup_failed: std::cell::Cell::new(false),
            provider,
            entry,
            catalogs: Vec::new(),
            authentication: Vec::new(),
        });
        // A discovery failure leaves a visible, unloadable module with a refresh action.
        let _ = self.discover(self.modules.len() - 1);
        Ok(id)
    }

    pub(super) fn execute(&mut self, command: BackendCommand) -> BackendEvent {
        let id = command.id();
        let previously_disabled: Vec<_> = self
            .modules
            .iter()
            .filter(|entry| entry.entry.discovery_error == Some(BackendError::SessionCleanup))
            .map(|entry| entry.entry.id)
            .collect();
        let event = self.execute_inner(command);
        // Even read-only commands can fail during close. Publish the disabled
        // inventory instead of leaving stale token actions enabled in the UI.
        let mut cleanup_failed = false;
        for index in 0..self.modules.len() {
            if self.modules[index].cleanup_failed.get()
                && !previously_disabled.contains(&self.modules[index].entry.id)
            {
                let _ = self.discover(index);
                cleanup_failed = true;
            }
        }
        if cleanup_failed {
            let loaded = match &event {
                BackendEvent::Completed {
                    result: Ok(BackendResult::Modules { loaded, .. }),
                    ..
                } => *loaded,
                _ => None,
            };
            BackendEvent::Completed {
                id,
                result: Ok(BackendResult::Modules {
                    modules: self
                        .modules
                        .iter()
                        .map(|entry| entry.entry.clone())
                        .collect(),
                    loaded,
                    error: Some(BackendError::SessionCleanup),
                }),
            }
        } else {
            event
        }
    }

    fn execute_inner(&mut self, command: BackendCommand) -> BackendEvent {
        let id = command.id();
        let mut loaded = None;
        let result = match command {
            BackendCommand::Administer {
                module,
                token,
                expected,
                role,
                action,
                ..
            } => {
                return BackendEvent::Completed {
                    id,
                    result: Ok(self.administer(module, token, expected, role, action)),
                };
            }
            BackendCommand::KeyOperation {
                scope,
                profile,
                job,
                ..
            } => {
                return BackendEvent::Completed {
                    id,
                    result: Ok(self.key_operation(scope, profile, job)),
                };
            }
            BackendCommand::Cipher { scope, job, .. } => {
                return BackendEvent::Completed {
                    id,
                    result: Ok(self.cipher(scope, job)),
                };
            }
            BackendCommand::Random {
                module,
                token,
                request,
                path,
                ..
            } => {
                return BackendEvent::Completed {
                    id,
                    result: self.random_file(module, token, request, &path).map(|()| {
                        BackendResult::RandomWritten {
                            length: request.length(),
                        }
                    }),
                };
            }
            BackendCommand::CryptoOptions {
                scope,
                software_hashing,
                ..
            } => {
                return BackendEvent::Completed {
                    id,
                    result: self.crypto_options(scope, software_hashing),
                };
            }
            BackendCommand::Crypto { scope, job, .. } => {
                return BackendEvent::Completed {
                    id,
                    result: self.crypto(scope, job),
                };
            }
            BackendCommand::Capabilities { module, token, .. } => {
                return BackendEvent::Completed {
                    id,
                    result: self.capabilities(module, token).map(|keys| {
                        BackendResult::Capabilities {
                            module,
                            token,
                            keys,
                        }
                    }),
                };
            }
            BackendCommand::Manage {
                module,
                token,
                action,
                ..
            } => {
                return BackendEvent::Completed {
                    id,
                    result: Ok(self.manage(module, token, action)),
                };
            }
            BackendCommand::Objects { module, token, .. } => {
                return BackendEvent::Completed {
                    id,
                    result: self
                        .objects(module, token)
                        .map(|objects| BackendResult::Objects {
                            module,
                            token,
                            objects,
                        }),
                };
            }
            BackendCommand::Mechanisms { module, token, .. } => {
                return BackendEvent::Completed {
                    id,
                    result: self.mechanisms(module, token).map(|mechanisms| {
                        BackendResult::Mechanisms {
                            module,
                            token,
                            mechanisms,
                        }
                    }),
                };
            }
            BackendCommand::Inspect {
                module,
                token,
                object,
                ..
            } => {
                return BackendEvent::Completed {
                    id,
                    result: self.inspect(module, token, object).map(|details| {
                        BackendResult::ObjectDetails {
                            module,
                            token,
                            object,
                            details,
                        }
                    }),
                };
            }
            BackendCommand::Login {
                module,
                token,
                role,
                pin,
                ..
            } => self.login(module, token, role, pin),
            BackendCommand::Logout { module, token, .. } => self.logout(module, token),
            BackendCommand::Load { path, .. } => {
                self.load(&path).map(|module| loaded = Some(module))
            }
            BackendCommand::Unload { module, .. } => {
                match self.modules.iter().position(|m| m.entry.id == module) {
                    Some(index) => self.modules.remove(index).close(),
                    None => Err(BackendError::UnknownModule),
                }
            }
            BackendCommand::Refresh { module, .. } => {
                match self.modules.iter().position(|m| m.entry.id == module) {
                    Some(index) => self.discover(index),
                    None => Err(BackendError::UnknownModule),
                }
            }
            #[cfg(test)]
            BackendCommand::Synthetic { outcome, .. } => {
                std::thread::sleep(std::time::Duration::from_millis(350));
                return BackendEvent::Completed {
                    id,
                    result: match outcome {
                        SyntheticOutcome::Success => Ok(BackendResult::Synthetic),
                        SyntheticOutcome::Failure => Err(BackendError::Synthetic),
                    },
                };
            }
            BackendCommand::Shutdown { .. } => unreachable!("shutdown is handled by the worker"),
        };
        BackendEvent::Completed {
            id,
            result: Ok(BackendResult::Modules {
                modules: self.modules.iter().map(|m| m.entry.clone()).collect(),
                loaded,
                error: result.err().or_else(|| {
                    loaded.and_then(|module| {
                        self.modules
                            .iter()
                            .find(|m| m.entry.id == module)
                            .and_then(|m| m.entry.discovery_error)
                    })
                }),
            }),
        }
    }

    pub(super) fn close(&mut self) -> Result<(), BackendError> {
        let mut error = None;
        for module in self.modules.drain(..) {
            if let Err(failure) = module.close() {
                error.get_or_insert(failure);
            }
        }
        error.map_or(Ok(()), Err)
    }
}
