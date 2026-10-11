// SPDX-License-Identifier: MIT OR Apache-2.0
use iced::futures::{Stream, StreamExt, channel::mpsc as asynchronous};
use pkcs11_client::{ErrorKind, Provider};
use std::path::{Path, PathBuf};
use std::{
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
};
mod authentication;
mod browse;
mod crypto;
mod management;
pub use authentication::{LoginRole, LoginState, SecretInput};
pub use browse::{MechanismEntry, MetadataField, ObjectEntry};
pub use crypto::{CryptoJob, CryptoMode, CryptoScope, SignatureOption};
pub use management::ManagementAction;

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
    pub login: LoginState,
    pub initialized: bool,
    pub user_pin_initialized: bool,
    pub user_pin_locked: bool,
    pub so_pin_locked: bool,
    pub write_protected: bool,
    pub protected_path: bool,
}
impl TokenEntry {
    pub fn can_login(&self, role: LoginRole) -> bool {
        self.initialized
            && self.uri.is_some()
            && self.login == LoginState::Public
            && match role {
                LoginRole::User => self.user_pin_initialized && !self.user_pin_locked,
                LoginRole::SecurityOfficer => !self.write_protected && !self.so_pin_locked,
            }
    }
    pub fn can_manage(&self) -> bool {
        self.initialized && !self.write_protected && self.login == LoginState::User
    }
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
    CryptoOptions {
        id: RequestId,
        scope: CryptoScope,
        software_hashing: bool,
    },
    Crypto {
        id: RequestId,
        scope: CryptoScope,
        job: CryptoJob,
    },
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
    Objects {
        id: RequestId,
        module: ResourceId,
        token: ResourceId,
    },
    Mechanisms {
        id: RequestId,
        module: ResourceId,
        token: ResourceId,
    },
    Inspect {
        id: RequestId,
        module: ResourceId,
        token: ResourceId,
        object: ResourceId,
    },
    #[cfg(test)]
    Synthetic {
        id: RequestId,
        outcome: SyntheticOutcome,
    },
    Login {
        id: RequestId,
        module: ResourceId,
        token: ResourceId,
        role: LoginRole,
        pin: SecretInput,
    },
    Logout {
        id: RequestId,
        module: ResourceId,
        token: ResourceId,
    },
    Capabilities {
        id: RequestId,
        module: ResourceId,
        token: ResourceId,
    },
    Manage {
        id: RequestId,
        module: ResourceId,
        token: ResourceId,
        action: ManagementAction,
    },
    Shutdown {
        id: RequestId,
    },
}
impl BackendCommand {
    pub fn id(&self) -> RequestId {
        match self {
            Self::Load { id, .. }
            | Self::CryptoOptions { id, .. }
            | Self::Crypto { id, .. }
            | Self::Unload { id, .. }
            | Self::Refresh { id, .. }
            | Self::Objects { id, .. }
            | Self::Mechanisms { id, .. }
            | Self::Inspect { id, .. }
            | Self::Login { id, .. }
            | Self::Logout { id, .. }
            | Self::Capabilities { id, .. }
            | Self::Manage { id, .. }
            | Self::Shutdown { id } => *id,
            #[cfg(test)]
            Self::Synthetic { id, .. } => *id,
        }
    }
}

#[derive(Clone, Debug)]
pub enum BackendResult {
    CryptoOptions {
        scope: CryptoScope,
        options: Vec<SignatureOption>,
        context: bool,
    },
    Verified {
        scope: CryptoScope,
    },
    Capabilities {
        module: ResourceId,
        token: ResourceId,
        keys: Vec<pkcs11_client::KeyKind>,
    },
    Managed {
        module: ResourceId,
        token: ResourceId,
        modules: Vec<ModuleEntry>,
        objects: Option<Vec<ObjectEntry>>,
        error: Option<BackendError>,
    },
    Objects {
        module: ResourceId,
        token: ResourceId,
        objects: Vec<ObjectEntry>,
    },
    Mechanisms {
        module: ResourceId,
        token: ResourceId,
        mechanisms: Vec<MechanismEntry>,
    },
    ObjectDetails {
        module: ResourceId,
        token: ResourceId,
        object: ResourceId,
        fields: Vec<MetadataField>,
    },
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
    SigningUnavailable,
    SignatureChoice,
    ContextRequired,
    CryptoRead,
    SignatureMismatch,
    Start,
    Busy,
    Disconnected,
    Panicked,
    #[cfg(test)]
    Synthetic,
    ModulePath,
    AlreadyLoaded,
    UnknownModule,
    UnknownToken,
    UnknownObject,
    AmbiguousObject,
    ResourceExhausted,
    RequestExhausted,
    AuthenticationUnavailable,
    AuthenticationFailed,
    ManagementUnavailable,
    RefreshAfterManagement,
    InvalidForm,
    FileRead,
    FileWrite,
    ExportUnavailable,
    Client(ErrorKind),
}
impl BackendError {
    pub fn message(self) -> &'static str {
        match self {
            Self::SigningUnavailable => {
                "Select a unique private key after USER login to sign, or a supported certificate to verify."
            }
            Self::SignatureChoice => {
                "Select a currently permitted signature choice and input/output files."
            }
            Self::ContextRequired => {
                "This key requires a per-operation PIN or protected authentication path."
            }
            Self::CryptoRead => {
                "Could not read the selected files. Message files are limited to 16 MiB and signatures to 16 KiB."
            }
            Self::SignatureMismatch => {
                "The signature is invalid for this certificate, input and parameters."
            }
            Self::ExportUnavailable => {
                "Only public certificates, public data and supported RSA/EC public keys can be exported."
            }
            Self::RefreshAfterManagement => {
                "The operation completed, but inventory refresh failed. Refresh before making another change."
            }
            Self::ManagementUnavailable => "Log in as USER on a writable token to manage objects.",
            Self::InvalidForm => {
                "Select an advertised key type and provide a label and a nonempty hexadecimal ID."
            }
            Self::FileRead => {
                "Could not read one DER certificate of at most 16 MiB from the selected file."
            }
            Self::FileWrite => {
                "Could not create or write the output file. Choose a new path; existing files are never overwritten. A failed operation may leave an empty or partial file."
            }
            Self::AuthenticationUnavailable => {
                "Authentication is unavailable for this role or token. Refresh its status."
            }
            Self::AuthenticationFailed => {
                "Authentication failed. Check the token status before submitting another login; failed attempts can lock the PIN."
            }
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
            Self::UnknownToken => {
                "The token is unavailable. Refresh the module and select the token again."
            }
            Self::UnknownObject => "The object is unavailable. Refresh the object list.",
            Self::AmbiguousObject => {
                "Multiple objects share this locator. Their details cannot be selected uniquely."
            }
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
    catalogs: Vec<browse::ObjectCatalog>,
    authentication: Vec<(ResourceId, pkcs11_client::ManagementSession<'static>)>,
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
        self.modules[index].catalogs.clear();
        let result = self.discover_inner(index);
        if let Err(error) = result {
            let entry = &mut self.modules[index].entry;
            entry.slots.clear();
            entry.tokens.clear();
            entry.discovery_error = Some(error);
            let _ = self.modules[index].close_authentication();
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
        self.modules.push(LoadedModule {
            provider,
            entry,
            catalogs: Vec::new(),
            authentication: Vec::new(),
        });
        // A discovery failure leaves a visible, unloadable module with a refresh action.
        let _ = self.discover(self.modules.len() - 1);
        Ok(id)
    }

    fn execute(&mut self, command: BackendCommand) -> BackendEvent {
        let id = command.id();
        let mut loaded = None;
        let result = match command {
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
                    result: self.inspect(module, token, object).map(|fields| {
                        BackendResult::ObjectDetails {
                            module,
                            token,
                            object,
                            fields,
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
            if let Err(failure) = module.close() {
                error.get_or_insert(failure);
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
mod tests;
