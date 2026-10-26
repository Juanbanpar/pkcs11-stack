// SPDX-License-Identifier: MIT OR Apache-2.0
/// Application workflow errors, without PINs, input bytes or certificate contents.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A random request is empty or exceeds the client allocation bound.
    #[error("random output length must be between 1 and 1048576 bytes")]
    InvalidRandomLength,
    /// Supplied signature is invalid for the selected certificate and input.
    #[error("signature verification failed")]
    SignatureMismatch,
    /// Public key attributes are absent, inconsistent or invalid for SPKI encoding.
    #[error("invalid or incomplete public key attributes")]
    InvalidPublicKey,
    /// Owned sessions still retain the module; close them before exclusive lifecycle work.
    #[error("provider still has live owned consumers")]
    ProviderInUse,
    /// The selected object class or privacy is outside the requested export boundary.
    #[error("object cannot be exported by this operation")]
    UnsupportedExport,
    /// A provider did not supply a requested attribute status.
    #[error("provider omitted attribute status")]
    MissingAttributeStatus,
    /// Runtime error preserving discovery, pool, policy and backend context.
    #[error(transparent)]
    Runtime(#[from] pkcs11_runtime::Error),
    /// Certificate or public-key encoding is not valid DER/X.509.
    #[error("invalid X.509 certificate or public key")]
    InvalidCertificate,
    /// The certificate public-key algorithm is outside the supported boundary.
    #[error("unsupported certificate public key")]
    UnsupportedCertificateKey,
    /// The selected key did not produce a signature verifiable by the certificate.
    #[error("key and certificate do not match, or signature verification failed")]
    KeyCertificateMismatch,
    /// No policy-permitted signing mechanism can prove the binding.
    #[error("no permitted mechanism for key/certificate binding")]
    NoBindingMechanism,
    /// A request cannot be independently verified by this client.
    #[error("unsupported signature verification parameters")]
    UnsupportedVerification,
}

/// Semantic error categories for application presentation, independent of exit codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Invalid request or unsupported input shape.
    Input,
    /// No match or ambiguous selection.
    Selection,
    /// Runtime policy, metadata or capability constraint.
    Policy,
    /// Provider, lifecycle, session or authentication failure.
    Runtime,
    /// Client certificate, binding or verification constraint.
    Client,
}
impl Error {
    /// Whether OAEP initialization rejected this profile's parameters.
    /// This does not authorize retries, digest downgrades or software fallback.
    pub fn oaep_parameters_rejected(&self) -> bool {
        matches!(self, Self::Runtime(error) if error.oaep_parameters_rejected())
    }
    /// Classify without requiring consumers to inspect runtime error variants.
    pub fn kind(&self) -> ErrorKind {
        use pkcs11_runtime::Error as Runtime;
        match self {
            Self::UnsupportedExport | Self::InvalidRandomLength => ErrorKind::Input,
            Self::MissingAttributeStatus | Self::ProviderInUse => ErrorKind::Runtime,
            Self::Runtime(error) => match error {
                Runtime::SignatureMismatch => ErrorKind::Client,
                Runtime::NotFound(_) | Runtime::Ambiguous { .. } => ErrorKind::Selection,
                Runtime::InvalidParameters(_)
                | Runtime::InvalidObjectReference
                | Runtime::InvalidTokenReference
                | Runtime::Locator(_) => ErrorKind::Input,
                Runtime::UnsupportedSigning(_)
                | Runtime::MissingMetadata(_)
                | Runtime::ContextAuthenticationRequired
                | Runtime::ProtectedPathUnavailable
                | Runtime::ReadWriteRequired
                | Runtime::RandomUnavailable => ErrorKind::Policy,
                Runtime::UnsupportedCipher
                | Runtime::UnsupportedKeyOperation
                | Runtime::UnsupportedAesGcm => ErrorKind::Policy,
                _ => ErrorKind::Runtime,
            },
            _ => ErrorKind::Client,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_omissions_are_not_classified_as_user_input() {
        assert_eq!(Error::MissingAttributeStatus.kind(), ErrorKind::Runtime);
        assert_eq!(Error::UnsupportedExport.kind(), ErrorKind::Input);
        assert_eq!(Error::InvalidRandomLength.kind(), ErrorKind::Input);
        assert_eq!(
            Error::Runtime(pkcs11_runtime::Error::SignatureMismatch).kind(),
            ErrorKind::Client
        );
        assert_eq!(
            Error::Runtime(pkcs11_runtime::Error::RandomUnavailable).kind(),
            ErrorKind::Policy
        );
    }
}
