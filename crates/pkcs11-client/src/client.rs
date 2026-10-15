// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::*;
use std::num::NonZeroUsize;

/// Synchronous application workflows over one runtime-owned session pool.
///
/// The client stores its pool and policy, never PINs or object handles. Share one
/// client per token/role; concurrent calls get exclusive runtime leases. All calls
/// are nonblocking at pool exhaustion and never retry signing or authentication.
pub struct Client<'m> {
    pool: SessionPool<'m>,
    policy: SigningPolicy,
}
impl<'m> Client<'m> {
    /// Use an existing runtime pool and explicit application signing policy.
    pub fn new(pool: SessionPool<'m>, policy: SigningPolicy) -> Self {
        Self { pool, policy }
    }
    /// Resolve a full token URI and create a read-only runtime pool.
    ///
    /// Rejects object criteria, authentication queries and unsupported selectors.
    /// The module is explicitly loaded by the application, never by this URI.
    pub fn connect(
        module: &'m Module,
        uri: &Pkcs11Uri,
        maximum: NonZeroUsize,
        policy: SigningPolicy,
    ) -> Result<Self, Error> {
        Ok(Self::new(
            SessionPool::new(
                module.resolve_token_uri(uri)?,
                SessionMode::ReadOnly,
                maximum,
            ),
            policy,
        ))
    }
    /// Application policy used for every signing operation and binding probe.
    pub fn policy(&self) -> &SigningPolicy {
        &self.policy
    }
    /// Access the runtime pool for explicit coordination, diagnostics or discard.
    pub fn pool(&self) -> &SessionPool<'m> {
        &self.pool
    }
    /// Resolve exactly one private key; retain its selector, never its handle.
    pub fn private_key(
        &self,
        uri: Pkcs11Uri,
        authentication: Authentication<'_>,
    ) -> Result<PrivateKeyRef, Error> {
        let key = PrivateKeyRef::new(uri)?;
        self.pool
            .try_acquire(authentication)?
            .session()
            .resolve(key.as_object_ref())?;
        Ok(key)
    }
    /// Resolve exactly one public key, independently of private-key association.
    pub fn public_key(
        &self,
        uri: Pkcs11Uri,
        authentication: Authentication<'_>,
    ) -> Result<PublicKeyRef, Error> {
        let key = PublicKeyRef::new(uri)?;
        self.pool
            .try_acquire(authentication)?
            .session()
            .resolve(key.as_object_ref())?;
        Ok(key)
    }
    /// Read a uniquely selected X.509 certificate; no trust decision is made.
    pub fn certificate(
        &self,
        uri: Pkcs11Uri,
        authentication: Authentication<'_>,
    ) -> Result<Certificate, Error> {
        let reference = CertificateRef::new(uri)?;
        let der = reference.der(self.pool.try_acquire(authentication)?.session())?;
        Certificate::from_der(der)
    }
    /// Read selected object attributes with the runtime's redacted value container.
    /// Explicitly requesting extractable secret attributes can expose secret data.
    pub fn attributes(
        &self,
        object: &ObjectRef,
        types: &[AttributeType],
        authentication: Authentication<'_>,
    ) -> Result<AttributeValues, Error> {
        let mut lease = self.pool.try_acquire(authentication)?;
        Ok(lease.session().resolve(object)?.read_attributes(types)?)
    }
    /// Read public metadata from a selected private key.
    pub fn public_metadata(
        &self,
        key: &PrivateKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<PublicKeyMetadata, Error> {
        Ok(key.public_metadata(self.pool.try_acquire(authentication)?.session())?)
    }
    /// Discover current key and token signing capabilities.
    pub fn capabilities(
        &self,
        key: &PrivateKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<KeyCapabilities, Error> {
        Ok(self
            .pool
            .try_acquire(authentication)?
            .session()
            .key_capabilities(key)?)
    }
    /// Common message-signing choices under current key capabilities and this policy.
    pub fn signing_options(
        &self,
        key: &PrivateKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<SigningOptions, Error> {
        Ok(crate::signature_options::options(
            &self.capabilities(key, authentication)?,
            &self.policy,
        ))
    }
    /// Inspect a plan under this client's policy without performing a signature.
    pub fn plan(
        &self,
        key: &PrivateKeyRef,
        request: &SignRequest<'_>,
        authentication: Authentication<'_>,
    ) -> Result<SignPlan, Error> {
        Ok(self
            .capabilities(key, authentication)?
            .plan(request, &self.policy)?)
    }
    /// Sign once, resolving the key and rediscovering its capabilities at execution.
    /// The runtime returns modulus-width RSA or fixed-width ECDSA r || s bytes.
    pub fn sign(
        &self,
        key: &PrivateKeyRef,
        request: &SignRequest<'_>,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.pool.try_acquire(authentication)?.session().sign(
            key,
            request,
            &self.policy,
            context_pin,
        )?)
    }
    /// Prove a key/certificate association with one token signature and verification.
    ///
    /// This operation signs a fixed domain-separated binding message. Candidate
    /// mechanisms are planned before execution; a failed signature is never retried.
    /// A required context PIN is borrowed for this operation only. Certificate trust
    /// remains application-owned. Identical labels/IDs do not establish a binding.
    pub fn bind_identity(
        &self,
        key: PrivateKeyRef,
        certificate: Certificate,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Identity, Error> {
        let mut lease = self.pool.try_acquire(authentication)?;
        let capabilities = lease.session().key_capabilities(&key)?;
        if capabilities.key != certificate.key_kind() {
            return Err(Error::KeyCertificateMismatch);
        }
        let request = binding_request(&capabilities, &self.policy)?;
        let signature = lease
            .session()
            .sign(&key, &request, &self.policy, context_pin)?;
        if let Err(error) = certificate.verify(&request, &signature) {
            lease.discard();
            return Err(error);
        }
        Ok(Identity { key, certificate })
    }
    /// Sign once and verify against the bound certificate before releasing output.
    ///
    /// Verification catches a replacement key under the same selector. PSS identity
    /// signing requires matching message/MGF digests; generic `sign` retains runtime
    /// support for independent MGF parameters. Unsupported verification fails before
    /// checkout or signing. No key handle, authentication or plan is cached.
    pub fn sign_identity(
        &self,
        identity: &Identity,
        request: &SignRequest<'_>,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        identity.certificate.validate_signing_request(request)?;
        let mut lease = self.pool.try_acquire(authentication)?;
        let signature = lease
            .session()
            .sign(&identity.key, request, &self.policy, context_pin)?;
        if let Err(error) = identity.certificate.verify(request, &signature) {
            lease.discard();
            return Err(error);
        }
        Ok(signature)
    }
}

/// Proven private-key selector and immutable certificate snapshot.
///
/// Does not assert certificate trust. Constructed only by `Client::bind_identity`.
/// Use `Client::sign_identity` to verify that each subsequent signature still matches.
#[derive(Debug)]
pub struct Identity {
    key: PrivateKeyRef,
    certificate: Certificate,
}
impl Identity {
    /// Stable key selector; using it directly opts out of per-signature association checks.
    pub fn key(&self) -> &PrivateKeyRef {
        &self.key
    }
    /// The certificate snapshot used for the binding and subsequent verification.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }
}

fn binding_request(
    capabilities: &KeyCapabilities,
    policy: &SigningPolicy,
) -> Result<SignRequest<'static>, Error> {
    let algorithms: &[SignatureAlgorithm] = match capabilities.key {
        KeyKind::Rsa { .. } => &[SignatureAlgorithm::RsaPss, SignatureAlgorithm::RsaPkcs1],
        KeyKind::Ec(_) => &[SignatureAlgorithm::Ecdsa],
    };
    for &algorithm in algorithms {
        for digest in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let request = SignRequest {
                algorithm,
                digest,
                input: SignInput::Message(b"pkcs11-client identity binding v1\0"),
                pss: (algorithm == SignatureAlgorithm::RsaPss).then_some(PssParameters {
                    mgf_digest: digest,
                    salt_len: digest.output_len(),
                }),
            };
            if capabilities.plan(&request, policy).is_ok() {
                return Ok(request);
            }
        }
    }
    Err(Error::NoBindingMechanism)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_runtime::{MechanismType, SigningMechanism};
    #[test]
    fn binding_respects_policy_and_key_restrictions() {
        let mut capabilities = KeyCapabilities {
            key: KeyKind::Rsa { bits: 2048 },
            can_sign: true,
            always_authenticate: false,
            allowed_mechanisms: None,
            mechanisms: vec![SigningMechanism {
                mechanism: MechanismType::SHA384_RSA_PKCS,
                can_sign: true,
                minimum_bits: 1024,
                maximum_bits: 4096,
            }],
        };
        let mut policy = SigningPolicy::default();
        let request = binding_request(&capabilities, &policy).unwrap();
        assert_eq!(request.algorithm, SignatureAlgorithm::RsaPkcs1);
        assert_eq!(request.digest, DigestAlgorithm::Sha384);
        policy.digests = vec![DigestAlgorithm::Sha256];
        assert!(matches!(
            binding_request(&capabilities, &policy),
            Err(Error::NoBindingMechanism)
        ));
        policy = SigningPolicy::default();
        capabilities.allowed_mechanisms = Some(vec![MechanismType::RSA_PKCS_PSS]);
        assert!(binding_request(&capabilities, &policy).is_err());
        capabilities.allowed_mechanisms = None;
        capabilities.can_sign = false;
        assert!(binding_request(&capabilities, &policy).is_err());
        capabilities.can_sign = true;
        capabilities.mechanisms[0].mechanism = MechanismType::RSA_PKCS;
        policy.hashing = HashingPolicy::SoftwareOnly;
        binding_request(&capabilities, &policy).unwrap();
        capabilities.always_authenticate = true;
        assert!(binding_request(&capabilities, &policy).is_err());
    }
}
