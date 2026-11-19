// SPDX-License-Identifier: MIT OR Apache-2.0
use std::path::PathBuf;

use pkcs11_client::ErrorKind;

use super::{
    AdministrationAction, CipherJob, CipherParameters, CryptoJob, CryptoScope, GenerationKind,
    KeyJob, KeyProfile, LoginRole, LoginState, ManagementAction, MechanismEntry, ObjectDetails,
    ObjectEntry, SecretInput, SignatureOption,
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
    pub initialization: pkcs11_client::TokenInitializationTarget,
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
    pub rng: bool,
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
    pub fn can_random(&self) -> bool {
        self.initialized && self.rng && self.uri.is_some()
    }
    pub(super) fn same_resource(&self, other: &Self) -> bool {
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
    Administer {
        id: RequestId,
        module: ResourceId,
        token: ResourceId,
        expected: pkcs11_client::TokenInitializationTarget,
        role: LoginState,
        action: AdministrationAction,
    },
    KeyOperation {
        id: RequestId,
        scope: CryptoScope,
        profile: KeyProfile,
        job: KeyJob,
    },
    Cipher {
        id: RequestId,
        scope: CryptoScope,
        job: CipherJob,
    },
    Random {
        id: RequestId,
        module: ResourceId,
        token: ResourceId,
        request: pkcs11_client::RandomRequest,
        path: PathBuf,
    },
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
            Self::Administer { id, .. }
            | Self::KeyOperation { id, .. }
            | Self::Load { id, .. }
            | Self::Cipher { id, .. }
            | Self::Random { id, .. }
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
    KeyOptions {
        scope: CryptoScope,
        profile: KeyProfile,
    },
    CipherOptions {
        scope: CryptoScope,
        choices: Vec<CipherParameters>,
    },
    RandomWritten {
        length: usize,
    },
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
        keys: Vec<GenerationKind>,
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
        details: ObjectDetails,
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
    AdministrationUnavailable,
    AdministrationInput,
    AdministrationFailed,
    SessionCleanup,
    KeyOperationUnavailable,
    KeyOperationInput,
    CipherUnavailable,
    OaepParametersRejected,
    CipherInput,
    RandomUnavailable,
    RandomLength,
    SigningUnavailable,
    SignatureChoice,
    MlDsaContext,
    PqcContext,
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
    MlKemImportInput,
    PublicKeyImportInput,
    HkdfInput,
    FileWrite,
    ExportUnavailable,
    Client(ErrorKind),
}
impl BackendError {
    pub fn message(self) -> &'static str {
        match self {
            Self::AdministrationUnavailable => {
                "Administration is unavailable for this token, role or changed selection. Refresh the token status. Protected-path administration is unsupported."
            }
            Self::AdministrationInput => {
                "Provide matching nonempty PINs within the advertised byte limits, a token label of 1–32 UTF-8 bytes, and explicit confirmation."
            }
            Self::SessionCleanup => {
                "A session could not be closed. Unload this module before using it again; an operation may have applied."
            }
            Self::AdministrationFailed => {
                "Administration failed. Changes may still have applied. No retry was made; check token status before authenticating again."
            }
            Self::KeyOperationUnavailable => {
                "Check key type, permissions, provider support and USER login. Creating keys requires a writable token."
            }
            Self::KeyOperationInput => {
                "Check the operation files, new secret label and hexadecimal ID. EC needs SPKI DER, AES needs a 24/32/40-byte wrapped blob, and ML-KEM ciphertext must match the displayed parameter set."
            }
            Self::OaepParametersRejected => {
                "The provider rejected these OAEP digest parameters. No digest downgrade or fallback was attempted."
            }
            Self::CipherUnavailable => {
                "Select a permitted RSA key or an AES secret key. AES and private-key operations require USER login. Per-operation-authentication RSA decryption is unsupported."
            }
            Self::CipherInput => {
                "Provide valid cipher parameters, bounded input, optional AAD and a new output path. AES-GCM requires a 24-digit hexadecimal nonce and a full tag."
            }
            Self::RandomUnavailable => {
                "Select an initialized token that advertises a random generator."
            }
            Self::RandomLength => {
                "Provide a byte count from 1 to 1048576 and a new output file path."
            }
            Self::SigningUnavailable => {
                "Select a unique private key after USER login to sign, or a supported certificate to verify."
            }
            Self::SignatureChoice => {
                "Select a currently permitted signature choice and input/output files."
            }
            Self::MlDsaContext => "ML-DSA context must contain at most 255 UTF-8 bytes.",
            Self::PqcContext => {
                "SLH-DSA and hash-PQC context must contain at most 255 UTF-8 bytes."
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
            Self::HkdfInput => {
                "Check the HKDF output length, hexadecimal salt (at most 4096 bytes), UTF-8 context (at most 4096 bytes), label and new hexadecimal ID."
            }
            Self::MlKemImportInput => {
                "Provide one ML-KEM SPKI DER public key of at most 2048 bytes, a label of 1–128 UTF-8 bytes and an ID of 1–128 hexadecimal bytes."
            }
            Self::PublicKeyImportInput => {
                "Provide one RSA/EC/EdDSA/Montgomery SPKI DER public key of at most 4096 bytes, a label of 1–128 UTF-8 bytes and an ID of 1–128 hexadecimal bytes."
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
