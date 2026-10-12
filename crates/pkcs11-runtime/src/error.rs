// SPDX-License-Identifier: MIT OR Apache-2.0
use std::fmt;

/// Runtime failure, preserving PKCS#11 operation and return-value context.
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Key class, permissions, context authentication or provider disallows OAEP.
    #[error("RSA OAEP operation unsupported for this key or provider")]
    UnsupportedCipher,
    /// Provider returned an output length inconsistent with the RSA modulus/profile.
    #[error("invalid RSA OAEP output length")]
    InvalidCiphertext,
    /// The token does not advertise its own random generator.
    #[error("token random generator unavailable")]
    RandomUnavailable,
    /// All pool slots are currently leased or being opened.
    #[error("session pool exhausted")]
    PoolExhausted,
    /// Pool synchronization was poisoned by a panic.
    #[error("session pool poisoned")]
    PoolPoisoned,
    /// Invalid bounds, input, or operation parameters.
    #[error("invalid operation parameters: {0}")]
    InvalidParameters(&'static str),
    /// Key metadata needed to make a safe decision is unavailable.
    #[error("required key metadata unavailable: {0}")]
    MissingMetadata(&'static str),
    /// No permitted implementation exists for the requested operation.
    #[error("unsupported signing request: {0}")]
    UnsupportedSigning(&'static str),
    /// The operation requires an explicit context-specific PIN.
    #[error("context-specific authentication required")]
    ContextAuthenticationRequired,
    /// Signature output is inconsistent with the selected algorithm.
    #[error("invalid signature length")]
    InvalidSignature,
    /// An upstream PKCS#11 call or library-loading operation failed.
    #[error("{operation}: {source}")]
    Backend {
        /// Runtime operation being attempted.
        operation: &'static str,
        /// Underlying cryptoki error, including PKCS#11 function/return value.
        #[source]
        source: cryptoki::error::Error,
    },
    /// Metadata failed after initialization, and finalization also failed.
    #[error("library info: {source}; initialization cleanup: {cleanup}")]
    InitializationCleanup {
        /// Primary metadata failure.
        #[source]
        source: cryptoki::error::Error,
        /// Secondary failure while finalizing the owned initialization.
        cleanup: cryptoki::error::Error,
    },
    /// The configured module path could not be canonicalized.
    #[error("module path: {0}")]
    ModulePath(#[source] std::io::Error),
    /// A locator could not be constructed or parsed.
    #[error("locator: {0}")]
    Locator(#[from] pkcs11_locator::Error),
    /// No token/object satisfied the selector.
    #[error("no matching {0}")]
    NotFound(&'static str),
    /// More than one token/object satisfied the selector.
    #[error("ambiguous {kind} selection ({count} matches)")]
    Ambiguous {
        /// Entity being resolved.
        kind: &'static str,
        /// Number of matches, never an arbitrary first match.
        count: usize,
    },
    /// Token metadata changed since discovery or session creation.
    #[error("token identity changed")]
    TokenChanged,
    /// The resource is closed, or a failed operation invalidated the session.
    #[error("resource is closed")]
    Closed,
    /// The token lacks a protected authentication path.
    #[error("protected authentication path is unavailable")]
    ProtectedPathUnavailable,
    /// The requested operation requires an RW session.
    #[error("operation requires a read-write session")]
    ReadWriteRequired,
    /// A persistent object URI lacks identity or contains unsupported constraints.
    #[error("unsupported persistent object reference")]
    InvalidObjectReference,
    /// A token URI contains object, authentication or unsupported constraints.
    #[error("unsupported token reference")]
    InvalidTokenReference,
}

impl Error {
    /// OAEP initialization specifically rejected the parameter shape.
    /// Other key, device and execution failures do not qualify for this category.
    pub fn oaep_parameters_rejected(&self) -> bool {
        matches!(
            self,
            Self::Backend {
                operation: "RSA OAEP encrypt" | "RSA OAEP decrypt",
                source: cryptoki::error::Error::Pkcs11(
                    cryptoki::error::RvError::ArgumentsBad
                        | cryptoki::error::RvError::MechanismParamInvalid,
                    cryptoki::context::Function::EncryptInit
                        | cryptoki::context::Function::DecryptInit
                )
            }
        )
    }
}
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Upstream Debug may include buffers (e.g. NulError); use its safe Display.
        write!(f, "Error({self})")
    }
}

pub(crate) fn backend(operation: &'static str, source: cryptoki::error::Error) -> Error {
    Error::Backend { operation, source }
}

pub(crate) fn unique<T>(mut matches: Vec<T>, kind: &'static str) -> Result<T, Error> {
    match matches.len() {
        0 => Err(Error::NotFound(kind)),
        1 => matches.pop().ok_or(Error::NotFound(kind)),
        count => Err(Error::Ambiguous { kind, count }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolution_never_chooses_an_arbitrary_match() {
        assert!(matches!(
            unique::<u8>(vec![], "token"),
            Err(Error::NotFound("token"))
        ));
        assert_eq!(unique(vec![7], "object").unwrap(), 7);
        assert!(matches!(
            unique(vec![7, 8], "object"),
            Err(Error::Ambiguous { count: 2, .. })
        ));
    }
    #[test]
    fn backend_preserves_return_code_without_debugging_input_buffers() {
        use cryptoki::{context::Function, error::RvError};
        let error = backend(
            "login",
            cryptoki::error::Error::Pkcs11(RvError::PinIncorrect, Function::Login),
        );
        assert!(matches!(
            error,
            Error::Backend {
                source: cryptoki::error::Error::Pkcs11(RvError::PinIncorrect, Function::Login),
                ..
            }
        ));
        let nul = std::ffi::CString::new(b"canary\0secret".to_vec()).unwrap_err();
        let error = backend("conversion", cryptoki::error::Error::NulError(nul));
        assert!(!format!("{error:?}").contains(&format!("{:?}", b"canary\0secret".to_vec())));
    }
    #[test]
    fn oaep_parameter_rejection_classification_is_specific_to_init() {
        use cryptoki::{context::Function, error::RvError};
        let init = backend(
            "RSA OAEP encrypt",
            cryptoki::error::Error::Pkcs11(RvError::ArgumentsBad, Function::EncryptInit),
        );
        assert!(init.oaep_parameters_rejected());
        let execution = backend(
            "RSA OAEP encrypt",
            cryptoki::error::Error::Pkcs11(RvError::ArgumentsBad, Function::Encrypt),
        );
        assert!(!execution.oaep_parameters_rejected());
        let key = backend(
            "RSA OAEP encrypt",
            cryptoki::error::Error::Pkcs11(RvError::KeyHandleInvalid, Function::EncryptInit),
        );
        assert!(!key.oaep_parameters_rejected());
    }
}
