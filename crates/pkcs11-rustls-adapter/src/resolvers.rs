// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Credential, Error};
use rustls::{
    SignatureScheme,
    client::ResolvesClientCert,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_pki_types::{DnsName, ServerName};
use std::{collections::BTreeMap, fmt, sync::Arc};

/// Server credentials routed by explicitly registered DNS names and offered schemes.
/// Multiple credentials for a name are tried in application-specified order.
/// Unknown SNI never uses the optional no-SNI default. No wildcard routing is inferred.
pub struct ServerResolver {
    names: BTreeMap<String, Vec<Arc<Credential>>>,
    default: Option<Arc<Credential>>,
}
impl fmt::Debug for ServerResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerResolver")
            .field("names", &self.names.len())
            .field("has_default", &self.default.is_some())
            .finish()
    }
}
impl ServerResolver {
    /// Register exact DNS names, checking each name against its leaf certificate.
    /// This checks name coverage only, not chain trust/validity. A default is used
    /// only for connections without SNI; callers own its intended identity policy.
    pub fn new(
        named: Vec<(String, Arc<Credential>)>,
        default: Option<Arc<Credential>>,
    ) -> Result<Self, Error> {
        let mut names: BTreeMap<String, Vec<Arc<Credential>>> = BTreeMap::new();
        for (name, credential) in named {
            let dns = DnsName::try_from(name.as_str()).map_err(|_| Error::InvalidServerName)?;
            let server = ServerName::DnsName(dns.to_owned());
            let certified = credential.certified_key();
            let leaf = certified.cert.first().ok_or(Error::EmptyChain)?;
            webpki::EndEntityCert::try_from(leaf)
                .map_err(|_| Error::InvalidCertificate)?
                .verify_is_valid_for_subject_name(&server)
                .map_err(|_| Error::ServerNameMismatch)?;
            names
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(credential);
        }
        Ok(Self { names, default })
    }
    /// Apply the same exact-name/scheme routing used by the rustls resolver.
    pub fn select(
        &self,
        name: Option<&str>,
        schemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        match name {
            Some(name) => self
                .names
                .get(&name.to_ascii_lowercase())?
                .iter()
                .find(|c| c.compatible(schemes))
                .map(|c| c.certified_key()),
            None => self
                .default
                .as_ref()
                .filter(|c| c.compatible(schemes))
                .map(|c| c.certified_key()),
        }
    }
}
impl ResolvesServerCert for ServerResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.select(hello.server_name(), hello.signature_schemes())
    }
}
/// Client credentials selected by peer signature schemes and exact DER issuer hints.
/// Empty hints allow any compatible configured identity; order is application policy.
pub struct ClientResolver {
    credentials: Vec<Arc<Credential>>,
}
impl fmt::Debug for ClientResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientResolver")
            .field("credentials", &self.credentials.len())
            .finish()
    }
}
impl ClientResolver {
    /// Configure ordered client identities; an empty list sends no client certificate.
    pub fn new(credentials: Vec<Arc<Credential>>) -> Self {
        Self { credentials }
    }
}
impl ResolvesClientCert for ClientResolver {
    fn has_certs(&self) -> bool {
        !self.credentials.is_empty()
    }
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.credentials
            .iter()
            .find(|c| {
                c.compatible(sigschemes)
                    && (root_hint_subjects.is_empty()
                        || c.issuers
                            .iter()
                            .any(|issuer| root_hint_subjects.contains(&issuer.as_slice())))
            })
            .map(|c| c.certified_key())
    }
}
