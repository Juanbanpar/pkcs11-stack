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

/// Clone an application provider with only X25519MLKEM768 and TLS 1.3 suites.
/// Returns an error when the provider lacks the hybrid group or TLS 1.3 suites.
/// Use the returned provider with TLS 1.3 for both peers to prevent classical fallback.
/// No software provider is selected, installed or added. Key exchange and the TLS
/// key schedule run in the supplied provider; token-backed signing is independent.
pub fn hybrid_tls13_provider(
    provider: &CryptoProvider,
) -> Result<Arc<CryptoProvider>, crate::Error> {
    let mut selected = provider.clone();
    selected
        .kx_groups
        .retain(|group| group.name() == rustls::NamedGroup::X25519MLKEM768);
    selected
        .cipher_suites
        .retain(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3);
    if selected.kx_groups.is_empty() || selected.cipher_suites.is_empty() {
        return Err(crate::Error::HybridKeyExchangeUnavailable);
    }
    Ok(Arc::new(selected))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hybrid_policy_requires_provider_support_and_leaves_the_source_unchanged() {
        let classical = rustls::crypto::ring::default_provider();
        assert!(matches!(
            hybrid_tls13_provider(&classical),
            Err(crate::Error::HybridKeyExchangeUnavailable)
        ));
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let count = provider.kx_groups.len();
        let selected = hybrid_tls13_provider(&provider).unwrap();
        assert!(
            selected
                .kx_groups
                .iter()
                .all(|group| group.name() == rustls::NamedGroup::X25519MLKEM768)
        );
        assert_eq!(selected.kx_groups.len(), 1);
        assert_eq!(provider.kx_groups.len(), count);
        assert!(server_config_builder(selected.clone(), &[&rustls::version::TLS12]).is_err());
        assert!(server_config_builder(selected, &[&rustls::version::TLS13]).is_ok());
        let mut no_suites = provider;
        no_suites.cipher_suites.clear();
        assert!(hybrid_tls13_provider(&no_suites).is_err());
    }
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
