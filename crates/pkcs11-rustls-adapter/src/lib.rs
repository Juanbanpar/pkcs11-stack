// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod config;
mod credentials;
mod encoding;
mod ml_dsa;
mod resolvers;
mod schemes;
mod signing;

pub use config::server_config_builder;
pub use credentials::{CredentialSource, Credentials, PinInput};
pub use resolvers::{ClientResolver, ServerResolver};
pub use signing::Credential;

/// Adapter errors contain no PINs, signing inputs or certificate contents.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Runtime discovery, policy, authentication or signing failure.
    #[error(transparent)]
    Runtime(#[from] pkcs11_runtime::Error),
    /// A credential source could not provide authentication for this operation.
    #[error("TLS signing credentials unavailable")]
    CredentialsUnavailable,
    /// A certificate chain must contain at least a leaf.
    #[error("certificate chain is empty")]
    EmptyChain,
    /// A supplied certificate is not valid exact X.509 DER.
    #[error("invalid certificate encoding")]
    InvalidCertificate,
    /// The leaf's public-key algorithm is unsupported.
    #[error("unsupported certificate public-key algorithm")]
    UnsupportedCertificateKey,
    /// No scheme intersects key, policy, provider and peer capabilities.
    #[error("no compatible TLS signature scheme")]
    NoCompatibleScheme,
    /// A token signature is not the exact expected encoding/width.
    #[error("invalid token signature encoding")]
    InvalidSignature,
    /// The signature does not verify against the retained leaf certificate.
    #[error("token signature does not match certificate")]
    KeyCertificateMismatch,
    /// A server registration has an invalid DNS name.
    #[error("invalid server DNS name")]
    InvalidServerName,
    /// A registered name is not covered by the leaf certificate.
    #[error("server name does not match certificate")]
    ServerNameMismatch,
}
