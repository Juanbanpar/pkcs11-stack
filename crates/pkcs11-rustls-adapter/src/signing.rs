// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{CredentialSource, Error, schemes};
use pkcs11_runtime::{
    KeyCapabilities, KeyKind, NamedCurve, PrivateKeyRef, SessionPool, SigningPolicy,
};
use rustls::{
    SignatureAlgorithm, SignatureScheme,
    crypto::CryptoProvider,
    sign::{CertifiedKey, Signer, SigningKey},
};
use rustls_pki_types::{CertificateDer, SubjectPublicKeyInfoDer};
use std::{fmt, sync::Arc};
use x509_cert::der::{
    Decode, Encode,
    asn1::{Null, ObjectIdentifier},
};

struct State {
    pool: Arc<SessionPool<'static>>,
    key: PrivateKeyRef,
    capabilities: KeyCapabilities,
    policy: SigningPolicy,
    source: Arc<dyn CredentialSource>,
    provider: Arc<CryptoProvider>,
    leaf: CertificateDer<'static>,
    spki: Vec<u8>,
}
impl State {
    fn verify(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        verify(&self.provider, &self.leaf, scheme, message, signature)
    }
}
fn verify(
    provider: &CryptoProvider,
    leaf: &CertificateDer<'_>,
    scheme: SignatureScheme,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let certificate =
        webpki::EndEntityCert::try_from(leaf).map_err(|_| Error::InvalidCertificate)?;
    let valid = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .filter(|(s, _)| *s == scheme)
        .flat_map(|(_, a)| a.iter())
        .any(|algorithm| {
            certificate
                .verify_signature(*algorithm, message, signature)
                .is_ok()
        });
    if valid {
        Ok(())
    } else {
        Err(Error::KeyCertificateMismatch)
    }
}
struct TokenKey(Arc<State>);
impl fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pkcs11SigningKey { key: [REDACTED] }")
    }
}
impl SigningKey for TokenKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = schemes::choose(
            offered,
            &self.0.capabilities,
            &self.0.policy,
            &self.0.provider,
        )?;
        Some(Box::new(TokenSigner {
            state: Arc::clone(&self.0),
            scheme,
        }))
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.0.spki.as_slice()))
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        match self.0.capabilities.key {
            KeyKind::Rsa { .. } => SignatureAlgorithm::RSA,
            KeyKind::Ec(_) => SignatureAlgorithm::ECDSA,
        }
    }
}
struct TokenSigner {
    state: Arc<State>,
    scheme: SignatureScheme,
}
impl fmt::Debug for TokenSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11Signer")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}
impl TokenSigner {
    fn sign_once(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let request = schemes::request(self.scheme, self.state.capabilities.key, message)
            .ok_or(Error::NoCompatibleScheme)?;
        let credentials = self.state.source.credentials()?;
        let mut lease = self.state.pool.try_acquire(credentials.authentication())?;
        let raw = lease.session().sign(
            &self.state.key,
            &request,
            &self.state.policy,
            credentials.context_pin(),
        )?;
        let signature = match crate::encoding::format_signature(self.state.capabilities.key, raw) {
            Ok(v) => v,
            Err(e) => {
                lease.discard();
                return Err(e);
            }
        };
        if let Err(error) = self.state.verify(self.scheme, message, &signature) {
            lease.discard();
            return Err(error);
        }
        Ok(signature)
    }
}
impl Signer for TokenSigner {
    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.sign_once(message)
            .map_err(|e| rustls::Error::General(e.to_string()))
    }
}
/// Proven token key and immutable leaf-first certificate chain for TLS authentication.
/// Binding and every subsequent signature are verified with the supplied provider.
/// This does not validate chain trust, dates, usage or revocation; peers/rustls do so.
pub struct Credential {
    certified: Arc<CertifiedKey>,
    pub(crate) issuers: Vec<Vec<u8>>,
}
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("chain_length", &self.certified.cert.len())
            .finish_non_exhaustive()
    }
}
impl Credential {
    /// Load a key and prove association using one domain-separated token signature.
    ///
    /// The source is invoked once. Planning picks a policy/provider-supported TLS
    /// scheme before signing; failure is never retried. The chain must be leaf-first.
    /// Only rsaEncryption and named-curve EC leaf keys are accepted initially.
    pub fn load(
        pool: Arc<SessionPool<'static>>,
        key: PrivateKeyRef,
        chain: Vec<CertificateDer<'static>>,
        policy: SigningPolicy,
        source: Arc<dyn CredentialSource>,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, Error> {
        let leaf = chain.first().ok_or(Error::EmptyChain)?.clone();
        let parsed = x509_cert::Certificate::from_der(leaf.as_ref())
            .map_err(|_| Error::InvalidCertificate)?;
        let public = &parsed.tbs_certificate.subject_public_key_info;
        let algorithm = &public.algorithm;
        let rsa = algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        let ec = algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
        if !rsa && !ec {
            return Err(Error::UnsupportedCertificateKey);
        }
        if rsa
            && algorithm
                .parameters
                .as_ref()
                .is_some_and(|p| p.decode_as::<Null>().is_err())
        {
            return Err(Error::UnsupportedCertificateKey);
        }
        let curve = if ec {
            let oid = algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                .ok_or(Error::UnsupportedCertificateKey)?;
            Some(match oid {
                oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7") => {
                    NamedCurve::P256
                }
                oid if oid == ObjectIdentifier::new_unwrap("1.3.132.0.34") => NamedCurve::P384,
                oid if oid == ObjectIdentifier::new_unwrap("1.3.132.0.35") => NamedCurve::P521,
                _ => return Err(Error::UnsupportedCertificateKey),
            })
        } else {
            None
        };
        let spki = public.to_der().map_err(|_| Error::InvalidCertificate)?;
        let mut issuers = Vec::new();
        for cert in &chain {
            let parsed = x509_cert::Certificate::from_der(cert.as_ref())
                .map_err(|_| Error::InvalidCertificate)?;
            issuers.push(
                parsed
                    .tbs_certificate
                    .issuer
                    .to_der()
                    .map_err(|_| Error::InvalidCertificate)?,
            );
        }
        let credentials = source.credentials()?;
        let mut lease = pool.try_acquire(credentials.authentication())?;
        let capabilities = lease.session().key_capabilities(&key)?;
        if rsa != matches!(capabilities.key, KeyKind::Rsa { .. })
            || curve.is_some_and(|c| capabilities.key != KeyKind::Ec(c))
        {
            return Err(Error::KeyCertificateMismatch);
        }
        let scheme = schemes::choose(schemes::PREFERENCE, &capabilities, &policy, &provider)
            .ok_or(Error::NoCompatibleScheme)?;
        let message = b"pkcs11-rustls-adapter credential binding v1\0";
        let request =
            schemes::request(scheme, capabilities.key, message).ok_or(Error::NoCompatibleScheme)?;
        let raw = lease
            .session()
            .sign(&key, &request, &policy, credentials.context_pin())?;
        let signature = match crate::encoding::format_signature(capabilities.key, raw) {
            Ok(v) => v,
            Err(e) => {
                lease.discard();
                return Err(e);
            }
        };
        if let Err(error) = verify(&provider, &leaf, scheme, message, &signature) {
            lease.discard();
            return Err(error);
        }
        drop(lease);
        let key = Arc::new(TokenKey(Arc::new(State {
            pool,
            key,
            capabilities,
            policy,
            source,
            provider,
            leaf,
            spki,
        })));
        let certified = Arc::new(CertifiedKey::new(chain, key));
        certified
            .keys_match()
            .map_err(|_| Error::KeyCertificateMismatch)?;
        Ok(Self { certified, issuers })
    }
    /// Borrow the proven rustls certificate/key bundle; contains no private key DER.
    pub fn certified_key(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.certified)
    }
    pub(crate) fn compatible(&self, schemes: &[SignatureScheme]) -> bool {
        self.certified.key.choose_scheme(schemes).is_some()
    }
}
