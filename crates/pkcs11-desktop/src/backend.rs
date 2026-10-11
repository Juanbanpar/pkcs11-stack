// SPDX-License-Identifier: GPL-3.0-or-later
use iced::futures::{Stream, StreamExt, channel::mpsc as asynchronous};
use pkcs11_client::{ErrorKind, Provider};
use std::path::{Path, PathBuf};
use std::{
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
};

/// Never reused during an application's lifetime, including after cancellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestId(pub u64);

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub enum SyntheticOutcome {
    Success,
    Failure,
}

/// Desktop identity; never a provider slot, session or object handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceId(pub u64);

#[derive(Clone, Debug)]
pub struct SlotEntry {
    pub id: u64,
    pub description: String,
    pub manufacturer: String,
    pub token_present: bool,
}

#[derive(Clone, Debug)]
pub struct TokenEntry {
    pub id: ResourceId,
    pub slot_id: u64,
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub uri: Option<String>,
    pub details: Vec<(String, String)>,
}
impl TokenEntry {
    fn same_resource(&self, other: &Self) -> bool {
        self.slot_id == other.slot_id
            && self.label == other.label
            && self.manufacturer == other.manufacturer
            && self.model == other.model
            && self.serial == other.serial
    }
}

#[derive(Clone, Debug)]
pub struct ModuleEntry {
    pub id: ResourceId,
    pub path: PathBuf,
    pub description: String,
    pub manufacturer: String,
    pub library_version: String,
    pub cryptoki_version: String,
    pub slots: Vec<SlotEntry>,
    pub tokens: Vec<TokenEntry>,
    pub discovery_error: Option<BackendError>,
}
impl ModuleEntry {
    pub fn label(&self) -> String {
        self.path
            .file_name()
            .unwrap_or(self.path.as_os_str())
            .to_string_lossy()
            .into_owned()
    }
}

// Command payloads are excluded from diagnostics.
pub enum BackendCommand {
    Load {
        id: RequestId,
        path: PathBuf,
    },
    Unload {
        id: RequestId,
        module: ResourceId,
    },
    Refresh {
        id: RequestId,
        module: ResourceId,
    },
    #[cfg(test)]
    Synthetic {
        id: RequestId,
        outcome: SyntheticOutcome,
    },
    Shutdown {
        id: RequestId,
    },
}
impl BackendCommand {
    pub fn id(&self) -> RequestId {
        match self {
            Self::Load { id, .. }
            | Self::Unload { id, .. }
            | Self::Refresh { id, .. }
            | Self::Shutdown { id } => *id,
            #[cfg(test)]
            Self::Synthetic { id, .. } => *id,
        }
    }
}

#[derive(Clone, Debug)]
pub enum BackendResult {
    Modules {
        modules: Vec<ModuleEntry>,
        loaded: Option<ResourceId>,
        error: Option<BackendError>,
    },
    #[cfg(test)]
    Synthetic,
}

/// Presentation data contains a category and fixed text, never raw diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendError {
    Start,
    Busy,
    Disconnected,
    Panicked,
    #[cfg(test)]
    Synthetic,
    ModulePath,
    AlreadyLoaded,
    UnknownModule,
    ResourceExhausted,
    RequestExhausted,
    Client(ErrorKind),
}
impl BackendError {
    pub fn message(self) -> &'static str {
        match self {
            Self::Start => "Could not start the background worker.",
            Self::Busy => "The worker queue is full. Wait before trying again.",
            Self::Disconnected => "The background worker is unavailable.",
            Self::Panicked => "The background worker stopped unexpectedly.",
            #[cfg(test)]
            Self::Synthetic => "The synthetic operation reported a test failure.",
            Self::RequestExhausted => "No more request IDs are available. Restart the application.",
            Self::ModulePath => {
                "Could not resolve the module file. Check its path and permissions."
            }
            Self::AlreadyLoaded => "This module is already loaded.",
            Self::UnknownModule => "The module is no longer loaded.",
            Self::ResourceExhausted => {
                "No more resource IDs are available. Restart the application."
            }
            Self::Client(ErrorKind::Input) => "The module metadata or request is invalid.",
            Self::Client(ErrorKind::Selection) => "The requested resource is missing or ambiguous.",
            Self::Client(ErrorKind::Runtime) => {
                "The provider operation failed. Check the module and token, then refresh or reload."
            }
            Self::Client(_) => "The client operation is unsupported or was rejected.",
        }
    }
}
impl From<&pkcs11_client::Error> for BackendError {
    fn from(error: &pkcs11_client::Error) -> Self {
        Self::Client(error.kind())
    }
}

#[derive(Clone, Debug)]
pub enum BackendEvent {
    Completed {
        id: RequestId,
        result: Result<BackendResult, BackendError>,
    },
    Stopped {
        id: RequestId,
        result: Result<(), BackendError>,
    },
    Disconnected,
}

/// One receiver per application; clones preserve the subscription's identity.
#[derive(Clone)]
pub struct EventSource(Arc<Mutex<Option<asynchronous::UnboundedReceiver<BackendEvent>>>>);
impl Hash for EventSource {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}
impl EventSource {
    pub fn stream(&self) -> impl Stream<Item = BackendEvent> + Unpin + use<> {
        let receiver = self.0.lock().expect("event source lock poisoned").take();
        // Report closure (including worker panic), instead of silently hanging UI state.
        iced::futures::stream::iter(receiver)
            .flatten()
            .chain(iced::futures::stream::once(iced::futures::future::ready(
                BackendEvent::Disconnected,
            )))
    }
}

/// Providers are created, used and finalized on the worker thread.
pub struct Worker {
    commands: Option<mpsc::SyncSender<BackendCommand>>,
    thread: Option<JoinHandle<Result<(), BackendError>>>,
}
impl Worker {
    pub fn spawn() -> Result<(Self, EventSource), BackendError> {
        let (commands, receiver) = mpsc::sync_channel(8);
        let (events, output) = asynchronous::unbounded();
        let thread = thread::Builder::new()
            .name("pkcs11-desktop-backend".into())
            .spawn(move || run(receiver, events))
            .map_err(|_| BackendError::Start)?;
        Ok((
            Self {
                commands: Some(commands),
                thread: Some(thread),
            },
            EventSource(Arc::new(Mutex::new(Some(output)))),
        ))
    }

    pub fn submit(&self, command: BackendCommand) -> Result<(), BackendError> {
        self.commands
            .as_ref()
            .ok_or(BackendError::Disconnected)?
            .try_send(command)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => BackendError::Busy,
                mpsc::TrySendError::Disconnected(_) => BackendError::Disconnected,
            })
    }

    /// Called ONLY by an Iced Task on its thread-pool executor, never update/view.
    /// Drains queued commands, asks the worker to stop, and joins it before exit.
    pub async fn shutdown(mut self, id: RequestId) -> Result<(), BackendError> {
        if let Some(sender) = self.commands.take() {
            // A full queue can block here; this future runs off the UI thread.
            let _ = sender.send(BackendCommand::Shutdown { id });
        }
        self.thread
            .take()
            .expect("worker join handle missing")
            .join()
            .map_err(|_| BackendError::Panicked)?
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Exceptional application teardown also disconnects the worker. Normal
        // window closure uses shutdown/join; Drop must never block the UI thread.
        self.commands.take();
    }
}

struct LoadedModule {
    provider: Provider,
    entry: ModuleEntry,
}
#[derive(Default)]
struct Registry {
    modules: Vec<LoadedModule>,
    next_resource: u64,
}
impl Registry {
    fn allocate(&mut self) -> Result<ResourceId, BackendError> {
        self.next_resource = self
            .next_resource
            .checked_add(1)
            .ok_or(BackendError::ResourceExhausted)?;
        Ok(ResourceId(self.next_resource))
    }

    fn discover(&mut self, index: usize) -> Result<(), BackendError> {
        let result = self.discover_inner(index);
        if let Err(error) = result {
            let entry = &mut self.modules[index].entry;
            entry.slots.clear();
            entry.tokens.clear();
            entry.discovery_error = Some(error);
        }
        result
    }

    fn discover_inner(&mut self, index: usize) -> Result<(), BackendError> {
        // Retain no sessions: discovery uses only the client's provider snapshots.
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
                id: ResourceId(0),
                slot_id: token.slot_id,
                label: info.label().into(),
                manufacturer: info.manufacturer_id().into(),
                model: info.model().into(),
                serial: info.serial_number().into(),
                uri: token.uri().ok().map(|uri| uri.to_string()),
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
        Ok(())
    }

    fn load(&mut self, path: &Path) -> Result<ResourceId, BackendError> {
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
        self.modules.push(LoadedModule { provider, entry });
        // A discovery failure leaves a visible, unloadable module with a refresh action.
        let _ = self.discover(self.modules.len() - 1);
        Ok(id)
    }

    fn execute(&mut self, command: BackendCommand) -> BackendEvent {
        let id = command.id();
        let mut loaded = None;
        let result = match command {
            BackendCommand::Load { path, .. } => {
                self.load(&path).map(|module| loaded = Some(module))
            }
            BackendCommand::Unload { module, .. } => {
                match self.modules.iter().position(|m| m.entry.id == module) {
                    Some(index) => self
                        .modules
                        .remove(index)
                        .provider
                        .finalize()
                        .map_err(|e| BackendError::from(&e)),
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
                thread::sleep(std::time::Duration::from_millis(350));
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

    fn close(&mut self) -> Result<(), BackendError> {
        let mut error = None;
        for module in self.modules.drain(..) {
            if let Err(failure) = module.provider.finalize() {
                error.get_or_insert(BackendError::from(&failure));
            }
        }
        error.map_or(Ok(()), Err)
    }
}

fn run(
    commands: mpsc::Receiver<BackendCommand>,
    events: asynchronous::UnboundedSender<BackendEvent>,
) -> Result<(), BackendError> {
    let mut registry = Registry::default();
    while let Ok(command) = commands.recv() {
        if let BackendCommand::Shutdown { id } = command {
            let result = registry.close();
            let _ = events.unbounded_send(BackendEvent::Stopped { id, result });
            return result;
        }
        if events.unbounded_send(registry.execute(command)).is_err() {
            break;
        }
    }
    registry.close()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced::futures::executor::block_on;

    #[test]
    fn command_round_trip_failure_and_shutdown_are_ordered() {
        let (worker, source) = Worker::spawn().unwrap();
        worker
            .submit(BackendCommand::Synthetic {
                id: RequestId(1),
                outcome: SyntheticOutcome::Success,
            })
            .unwrap();
        worker
            .submit(BackendCommand::Synthetic {
                id: RequestId(2),
                outcome: SyntheticOutcome::Failure,
            })
            .unwrap();
        block_on(worker.shutdown(RequestId(3))).unwrap();
        let events: Vec<_> = block_on(source.stream().collect());
        assert!(matches!(
            events.as_slice(),
            [
                BackendEvent::Completed {
                    id: RequestId(1),
                    result: Ok(BackendResult::Synthetic)
                },
                BackendEvent::Completed {
                    id: RequestId(2),
                    result: Err(BackendError::Synthetic)
                },
                BackendEvent::Stopped {
                    id: RequestId(3),
                    result: Ok(())
                },
                BackendEvent::Disconnected
            ]
        ));
    }

    #[test]
    fn dropping_worker_disconnects_and_terminates_it() {
        let (mut worker, source) = Worker::spawn().unwrap();
        let handle = worker.thread.take().unwrap();
        drop(worker);
        handle.join().unwrap().unwrap();
        assert!(matches!(
            block_on(source.stream().next()),
            Some(BackendEvent::Disconnected)
        ));
    }

    #[test]
    fn queue_full_and_disconnected_are_typed_failures() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = Worker {
            commands: Some(sender),
            thread: None,
        };
        let command = || BackendCommand::Synthetic {
            id: RequestId(1),
            outcome: SyntheticOutcome::Success,
        };
        worker.submit(command()).unwrap();
        assert_eq!(worker.submit(command()), Err(BackendError::Busy));
        drop(receiver);
        assert_eq!(worker.submit(command()), Err(BackendError::Disconnected));
    }

    #[test]
    fn worker_panic_is_reported_at_join_and_stream_closure() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let (events, output) = asynchronous::unbounded();
        let worker = Worker {
            commands: Some(sender),
            thread: Some(thread::spawn(move || {
                let _keep_channels_alive = (receiver, events);
                panic!("synthetic worker panic");
            })),
        };
        assert_eq!(
            block_on(worker.shutdown(RequestId(1))),
            Err(BackendError::Panicked)
        );
        let source = EventSource(Arc::new(Mutex::new(Some(output))));
        assert!(matches!(
            block_on(source.stream().next()),
            Some(BackendEvent::Disconnected)
        ));
    }

    #[test]
    fn cleanup_failure_is_returned_after_the_worker_is_joined() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let failure = BackendError::Client(ErrorKind::Runtime);
        let worker = Worker {
            commands: Some(sender),
            thread: Some(thread::spawn(move || {
                assert!(matches!(
                    receiver.recv().unwrap(),
                    BackendCommand::Shutdown { .. }
                ));
                Err(failure)
            })),
        };
        assert_eq!(block_on(worker.shutdown(RequestId(1))), Err(failure));
    }

    #[test]
    fn client_ownership_traits_support_worker_local_use() {
        fn send<T: Send>() {}
        fn share<T: Send + Sync>() {}
        share::<pkcs11_client::Provider>();
        share::<pkcs11_client::Client<'static>>();
        send::<pkcs11_client::ManagementSession<'static>>();
    }
    fn inventory(
        event: BackendEvent,
    ) -> (Vec<ModuleEntry>, Option<ResourceId>, Option<BackendError>) {
        match event {
            BackendEvent::Completed {
                result:
                    Ok(BackendResult::Modules {
                        modules,
                        loaded,
                        error,
                    }),
                ..
            } => (modules, loaded, error),
            other => panic!("unexpected event: {other:?}"),
        }
    }
    #[test]
    fn invalid_paths_and_unknown_modules_return_inventory_with_fixed_errors() {
        let mut registry = Registry::default();
        let path = std::env::temp_dir().join("missing-directory-desktop-test/module-pin-canary.so");
        let (modules, loaded, error) = inventory(registry.execute(BackendCommand::Load {
            id: RequestId(1),
            path,
        }));
        assert!(modules.is_empty());
        assert!(loaded.is_none());
        assert_eq!(error, Some(BackendError::ModulePath));
        assert!(!format!("{error:?} {}", error.unwrap().message()).contains("pin-canary"));
        for command in [
            BackendCommand::Refresh {
                id: RequestId(2),
                module: ResourceId(9),
            },
            BackendCommand::Unload {
                id: RequestId(3),
                module: ResourceId(9),
            },
        ] {
            assert_eq!(
                inventory(registry.execute(command)).2,
                Some(BackendError::UnknownModule)
            );
        }
        registry.next_resource = u64::MAX;
        assert_eq!(registry.allocate(), Err(BackendError::ResourceExhausted));
    }
    #[test]
    fn backend_failure_reaches_ui_without_loading_vendor_code() {
        let (worker, source) = Worker::spawn().unwrap();
        worker
            .submit(BackendCommand::Refresh {
                id: RequestId(1),
                module: ResourceId(44),
            })
            .unwrap();
        let event = block_on(source.stream().next()).unwrap();
        assert_eq!(inventory(event).2, Some(BackendError::UnknownModule));
        block_on(worker.shutdown(RequestId(2))).unwrap();
    }
    #[test]
    fn public_token_identity_distinguishes_replacement_in_the_same_slot() {
        let a = TokenEntry {
            id: ResourceId(1),
            slot_id: 2,
            label: String::new(),
            manufacturer: "Maker".into(),
            model: "Model".into(),
            serial: "A".into(),
            uri: None,
            details: Vec::new(),
        };
        let mut b = a.clone();
        b.details.push(("Initialized".into(), "true".into()));
        assert!(a.same_resource(&b));
        b.serial = "B".into();
        assert!(!a.same_resource(&b));
        b.serial = "A".into();
        b.slot_id = 3;
        assert!(!a.same_resource(&b));
    }

    #[test]
    #[ignore = "requires the isolated SoftHSM runner"]
    fn software_token_browser_load_refresh_unload_and_shutdown() {
        assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
        let path = PathBuf::from(std::env::var_os("PKCS11_TEST_MODULE").unwrap());
        let (worker, source) = Worker::spawn().unwrap();
        let mut events = source.stream();
        worker
            .submit(BackendCommand::Load {
                id: RequestId(1),
                path: path.clone(),
            })
            .unwrap();
        let (modules, loaded, error) = inventory(block_on(events.next()).unwrap());
        assert!(error.is_none());
        assert_eq!(modules.len(), 1);
        let module = &modules[0];
        let module_id = loaded.unwrap();
        assert_eq!(module.id, module_id);
        assert_eq!(module.path, path.canonicalize().unwrap());
        assert!(!module.description.is_empty());
        assert!(!module.slots.is_empty());
        assert!(
            module
                .tokens
                .iter()
                .filter(|t| t.label == "runtime-test")
                .count()
                >= 2
        );
        let mut identities: Vec<_> = module
            .tokens
            .iter()
            .map(|t| (t.id, t.serial.clone()))
            .collect();
        identities.sort_by_key(|(id, _)| id.0);
        let distinct: std::collections::HashSet<_> = module.tokens.iter().map(|t| t.id.0).collect();
        assert_eq!(distinct.len(), module.tokens.len());
        for token in &module.tokens {
            let uri: pkcs11_client::Pkcs11Uri = token.uri.as_ref().unwrap().parse().unwrap();
            pkcs11_client::validate_token_uri(&uri).unwrap();
            assert!(!uri.to_string().contains("pin-value"));
        }
        // Dot components resolve to the same owner; a duplicate must not finalize it.
        let alias = path
            .parent()
            .unwrap()
            .join(".")
            .join(path.file_name().unwrap());
        worker
            .submit(BackendCommand::Load {
                id: RequestId(2),
                path: alias,
            })
            .unwrap();
        let (duplicates, _, error) = inventory(block_on(events.next()).unwrap());
        assert_eq!(error, Some(BackendError::AlreadyLoaded));
        assert_eq!(duplicates.len(), 1);
        worker
            .submit(BackendCommand::Refresh {
                id: RequestId(3),
                module: module_id,
            })
            .unwrap();
        let (refreshed, _, error) = inventory(block_on(events.next()).unwrap());
        assert!(error.is_none());
        let mut refreshed_identities: Vec<_> = refreshed[0]
            .tokens
            .iter()
            .map(|t| (t.id, t.serial.clone()))
            .collect();
        refreshed_identities.sort_by_key(|(id, _)| id.0);
        assert_eq!(identities, refreshed_identities);
        worker
            .submit(BackendCommand::Unload {
                id: RequestId(4),
                module: module_id,
            })
            .unwrap();
        let (modules, _, error) = inventory(block_on(events.next()).unwrap());
        assert!(modules.is_empty());
        assert!(error.is_none());
        worker
            .submit(BackendCommand::Load {
                id: RequestId(5),
                path: path.clone(),
            })
            .unwrap();
        let (modules, reloaded, error) = inventory(block_on(events.next()).unwrap());
        assert!(error.is_none());
        assert_eq!(modules.len(), 1);
        assert_ne!(reloaded, Some(module_id));
        // Successful reloading proves both explicit unload and shutdown finalized the owner.
        block_on(worker.shutdown(RequestId(6))).unwrap();
        drop(events);
        let provider = Provider::load(path).unwrap();
        assert!(!provider.tokens().unwrap().is_empty());
        provider.finalize().unwrap();
    }
}
