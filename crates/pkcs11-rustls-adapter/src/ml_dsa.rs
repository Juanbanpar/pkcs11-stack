// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Credential, CredentialSource, Error,
    signing::{chain_issuers, verify},
};
use pkcs11_runtime::{
    MlDsaCapabilities, MlDsaHedging, MlDsaParameterSet, MlDsaRequest, MlDsaSigningPolicy,
    PrivateKeyRef, SessionPool,
};
use rustls::{
    SignatureAlgorithm, SignatureScheme,
    crypto::CryptoProvider,
    sign::{CertifiedKey, Signer, SigningKey},
};
use rustls_pki_types::{
    CertificateDer, SubjectPublicKeyInfoDer,
    alg_id::{self, AlgorithmIdentifier},
};
use std::{fmt, sync::Arc};
use x509_cert::der::{Decode, Encode, asn1::ObjectIdentifier};

fn scheme(parameter: MlDsaParameterSet) -> SignatureScheme {
    match parameter {
        MlDsaParameterSet::MlDsa44 => SignatureScheme::ML_DSA_44,
        MlDsaParameterSet::MlDsa65 => SignatureScheme::ML_DSA_65,
        MlDsaParameterSet::MlDsa87 => SignatureScheme::ML_DSA_87,
    }
}
fn algorithm_id(parameter: MlDsaParameterSet) -> AlgorithmIdentifier {
    match parameter {
        MlDsaParameterSet::MlDsa44 => alg_id::ML_DSA_44,
        MlDsaParameterSet::MlDsa65 => alg_id::ML_DSA_65,
        MlDsaParameterSet::MlDsa87 => alg_id::ML_DSA_87,
    }
}
fn leaf_key(leaf: &CertificateDer<'_>) -> Result<(MlDsaParameterSet, Vec<u8>), Error> {
    let parsed =
        x509_cert::Certificate::from_der(leaf.as_ref()).map_err(|_| Error::InvalidCertificate)?;
    let public = parsed.tbs_certificate.subject_public_key_info;
    let parameter = [
        ("2.16.840.1.101.3.4.3.17", MlDsaParameterSet::MlDsa44),
        ("2.16.840.1.101.3.4.3.18", MlDsaParameterSet::MlDsa65),
        ("2.16.840.1.101.3.4.3.19", MlDsaParameterSet::MlDsa87),
    ]
    .into_iter()
    .find(|(oid, _)| public.algorithm.oid == ObjectIdentifier::new_unwrap(oid))
    .map(|(_, parameter)| parameter)
    .ok_or(Error::UnsupportedCertificateKey)?;
    if public.algorithm.parameters.is_some()
        || public.subject_public_key.as_bytes().map(<[u8]>::len)
            != Some(parameter.public_key_length())
    {
        return Err(Error::InvalidCertificate);
    }
    Ok((
        parameter,
        public.to_der().map_err(|_| Error::InvalidCertificate)?,
    ))
}
fn has_verifier(provider: &CryptoProvider, parameter: MlDsaParameterSet) -> bool {
    let expected = algorithm_id(parameter);
    provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .any(|(mapped, algorithms)| {
            *mapped == scheme(parameter)
                && algorithms.iter().any(|algorithm| {
                    algorithm.public_key_alg_id() == expected
                        && algorithm.signature_alg_id() == expected
                })
        })
}
fn request(parameter_set: MlDsaParameterSet, message: &[u8]) -> MlDsaRequest<'_> {
    // TLS CertificateVerify already contains its protocol context. FIPS 204 ctx is empty.
    MlDsaRequest {
        parameter_set,
        message,
        context: b"",
        hedging: MlDsaHedging::Required,
    }
}

struct State {
    pool: Arc<SessionPool<'static>>,
    key: PrivateKeyRef,
    capabilities: MlDsaCapabilities,
    policy: MlDsaSigningPolicy,
    source: Arc<dyn CredentialSource>,
    provider: Arc<CryptoProvider>,
    leaf: CertificateDer<'static>,
    spki: Vec<u8>,
}
struct TokenKey(Arc<State>);
impl fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pkcs11MlDsaSigningKey { key: [REDACTED] }")
    }
}
impl SigningKey for TokenKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let parameter = self.0.capabilities.parameter_set;
        if !offered.contains(&scheme(parameter))
            || self
                .0
                .capabilities
                .validate(&request(parameter, b""), &self.0.policy)
                .is_err()
        {
            return None;
        }
        Some(Box::new(TokenSigner(Arc::clone(&self.0))))
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.0.spki.as_slice()))
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        // Rustls uses the full ML-DSA SignatureScheme; no legacy TLS 1.2 algorithm exists.
        SignatureAlgorithm::Unknown(0)
    }
}
struct TokenSigner(Arc<State>);
impl fmt::Debug for TokenSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11MlDsaSigner")
            .field("scheme", &scheme(self.0.capabilities.parameter_set))
            .finish_non_exhaustive()
    }
}
impl TokenSigner {
    fn sign_once(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let state = &self.0;
        let credentials = state.source.credentials()?;
        let mut lease = state.pool.try_acquire(credentials.authentication())?;
        let signature = lease.session().sign_ml_dsa(
            &state.key,
            &request(state.capabilities.parameter_set, message),
            &state.policy,
            credentials.context_pin(),
        )?;
        if let Err(error) = verify(
            &state.provider,
            &state.leaf,
            scheme(state.capabilities.parameter_set),
            message,
            &signature,
        ) {
            lease.discard();
            return Err(error);
        }
        Ok(signature)
    }
}
impl Signer for TokenSigner {
    fn scheme(&self) -> SignatureScheme {
        scheme(self.0.capabilities.parameter_set)
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.sign_once(message)
            .map_err(|e| rustls::Error::General(e.to_string()))
    }
}
impl Credential {
    /// Load an ML-DSA-44/65/87 identity for TLS 1.3, with required hedging and empty
    /// FIPS 204 context. The application provider must verify that parameter set.
    ///
    /// A single probe proves the key/leaf association; each later signature is
    /// independently verified. No signing, authentication or provider fallback is
    /// retried. Policy, certificate and provider checks precede credential acquisition.
    /// Loading establishes no certificate-chain trust, time, usage or revocation status.
    pub fn load_ml_dsa(
        pool: Arc<SessionPool<'static>>,
        key: PrivateKeyRef,
        chain: Vec<CertificateDer<'static>>,
        policy: MlDsaSigningPolicy,
        source: Arc<dyn CredentialSource>,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, Error> {
        let leaf = chain.first().ok_or(Error::EmptyChain)?.clone();
        let (parameter, spki) = leaf_key(&leaf)?;
        let issuers = chain_issuers(&chain)?;
        let message = b"pkcs11-rustls-adapter ML-DSA credential binding v1\0";
        let request = request(parameter, message);
        policy.validate(&request)?;
        if !has_verifier(&provider, parameter) {
            return Err(Error::NoCompatibleScheme);
        }
        let credentials = source.credentials()?;
        let mut lease = pool.try_acquire(credentials.authentication())?;
        let capabilities = lease.session().ml_dsa_capabilities(&key)?;
        if capabilities.parameter_set != parameter {
            return Err(Error::KeyCertificateMismatch);
        }
        capabilities.validate(&request, &policy)?;
        let signature =
            lease
                .session()
                .sign_ml_dsa(&key, &request, &policy, credentials.context_pin())?;
        if let Err(error) = verify(&provider, &leaf, scheme(parameter), message, &signature) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::asn1::{Any, BitString};
    #[test]
    fn ml_dsa_requires_exact_parameters_and_matching_provider_verification() {
        let fixtures = [
            (
                MlDsaParameterSet::MlDsa44,
                include_bytes!("../../pkcs11-client/tests/fixtures/mldsa44.der").as_slice(),
            ),
            (
                MlDsaParameterSet::MlDsa65,
                include_bytes!("../../pkcs11-client/tests/fixtures/mldsa65.der").as_slice(),
            ),
            (
                MlDsaParameterSet::MlDsa87,
                include_bytes!("../../pkcs11-client/tests/fixtures/mldsa87.der").as_slice(),
            ),
        ];
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let ring = rustls::crypto::ring::default_provider();
        for (parameter, der) in fixtures {
            let leaf = CertificateDer::from(der);
            assert_eq!(leaf_key(&leaf).unwrap().0, parameter);
            assert!(has_verifier(&provider, parameter));
            assert!(!has_verifier(&ring, parameter));
            let mut wrong = provider.clone();
            static WRONG: &[(
                SignatureScheme,
                &[&dyn rustls_pki_types::SignatureVerificationAlgorithm],
            )] = &[(SignatureScheme::ML_DSA_44, &[webpki::aws_lc_rs::ML_DSA_65])];
            wrong.signature_verification_algorithms.mapping = WRONG;
            assert!(!has_verifier(&wrong, parameter));
            let request = request(parameter, b"TLS CertificateVerify");
            assert!(request.context.is_empty());
            assert_eq!(request.hedging, MlDsaHedging::Required);
            let parsed = x509_cert::Certificate::from_der(der).unwrap();
            let mut null = parsed.clone();
            null.tbs_certificate
                .subject_public_key_info
                .algorithm
                .parameters = Some(Any::from_der(&[5, 0]).unwrap());
            let mut truncated = parsed.clone();
            truncated
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key = BitString::from_bytes(&[0; 32]).unwrap();
            let mut unaligned = parsed;
            unaligned
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key =
                BitString::new(1, vec![0; parameter.public_key_length()]).unwrap();
            for bad in [null, truncated, unaligned] {
                assert!(matches!(
                    leaf_key(&CertificateDer::from(bad.to_der().unwrap())),
                    Err(Error::InvalidCertificate)
                ));
            }
        }
    }
}
