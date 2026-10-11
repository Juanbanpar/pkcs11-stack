// SPDX-License-Identifier: MIT OR Apache-2.0
use rustls::{
    ConfigBuilder, ServerConfig, SupportedProtocolVersion, WantsVerifier, crypto::CryptoProvider,
};
use std::sync::Arc;

/// Start a server configuration with suites restricted to the enabled TLS versions.
///
/// Use this before selecting client authentication and attaching `ServerResolver`.
/// The application still supplies the crypto provider, protocol versions and trust
/// policy. The provider is cloned; its algorithms, suite order and other consumers
/// are unchanged. No global provider is selected or installed.
///
/// Rustls 0.23.43 filters resolver signature schemes against provider suites before
/// filtering those suites by the negotiated version. Keeping disabled-version
/// suites can therefore select an RSA credential for a TLS 1.2 client that offers
/// only ECDSA TLS 1.2 suites alongside TLS 1.3 suites. This builder excludes such
/// disabled suites before rustls performs certificate selection.
pub fn server_config_builder(
    provider: Arc<CryptoProvider>,
    versions: &[&'static SupportedProtocolVersion],
) -> Result<ConfigBuilder<ServerConfig, WantsVerifier>, rustls::Error> {
    let mut provider = (*provider).clone();
    provider.cipher_suites.retain(|suite| {
        versions
            .iter()
            .any(|version| version.version == suite.version().version)
    });
    ServerConfig::builder_with_provider(Arc::new(provider)).with_protocol_versions(versions)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_empty_or_incompatible_versions_without_mutating_provider() {
        let mut provider = rustls::crypto::ring::default_provider();
        provider
            .cipher_suites
            .retain(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3);
        let provider = Arc::new(provider);
        let suites = provider
            .cipher_suites
            .iter()
            .map(|suite| suite.suite())
            .collect::<Vec<_>>();
        assert!(server_config_builder(provider.clone(), &[]).is_err());
        assert!(server_config_builder(provider.clone(), &[&rustls::version::TLS12]).is_err());
        assert!(server_config_builder(provider.clone(), &[&rustls::version::TLS13]).is_ok());
        assert_eq!(
            suites,
            provider
                .cipher_suites
                .iter()
                .map(|suite| suite.suite())
                .collect::<Vec<_>>()
        );
    }
}
