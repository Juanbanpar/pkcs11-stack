// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, DigestAlgorithm, Error, HkdfRequest, MechanismType, ObjectRef, Session, SessionMode,
    error::backend,
    hkdf::{permits, secret_length},
};
use cryptoki::{
    context::Function,
    mechanism::{
        Mechanism,
        hkdf::{HkdfParams, HkdfSalt},
    },
    object::KeyType,
};

fn finish(
    outcome: Result<(), cryptoki::error::Error>,
    cleanup: Result<(), cryptoki::error::Error>,
) -> Result<(), Error> {
    match cleanup {
        Err(cleanup) => Err(Error::HybridCleanup {
            primary: outcome.err(),
            cleanup,
        }),
        Ok(()) => outcome.map_err(|error| backend("derive hybrid HKDF key", error)),
    }
}
impl HkdfRequest<'_> {
    /// Validate the P-256 || ML-KEM-768 application combiner profile without I/O.
    /// Requires SHA-512, public salt at most 128 bytes and nonempty protocol context.
    pub fn validate_hybrid(&self) -> Result<(), Error> {
        self.validate()?;
        if self.digest != DigestAlgorithm::Sha512 || self.salt.len() > 128 || self.info.is_empty() {
            return Err(Error::InvalidParameters(
                "hybrid HKDF requires SHA-512, salt at most 128 bytes and nonempty protocol context",
            ));
        }
        Ok(())
    }
}
fn component(object: &crate::Object<'_, '_>) -> Result<(), Error> {
    if secret_length(object)? != 32
        || !matches!(
            crate::signing::attribute(object, crate::AttributeType::KeyType, true)?,
            Some(Attribute::KeyType(KeyType::GENERIC_SECRET))
        )
    {
        return Err(Error::UnsupportedKeyOperation);
    }
    permits(object, MechanismType::CONCATENATE_BASE_AND_KEY)
}
impl Session<'_> {
    /// Combine a P-256 ECDH secret followed by an ML-KEM-768 secret and run HKDF-SHA512.
    /// Both inputs must be distinct sensitive, nonextractable 32-byte generic secrets
    /// with derivation permission. The caller is responsible for their provenance,
    /// independent generation, peer authentication and protocol-bound context.
    /// This follows SP 800-56C's classical || auxiliary construction; it defines no
    /// wire protocol, X-Wing KEM or TLS key schedule and makes no validation claim.
    /// Salt is public, at most 128 bytes; info must be nonempty and at most 4096 bytes.
    /// The concatenated 64-byte secret is a session object, destroyed before return.
    /// Requires RW mode. Output restrictions match `derive_hkdf`; no values leave
    /// the token. Cleanup errors invalidate the session and take precedence; even
    /// failure can leave persistent output. No rollback, retry or fallback occurs.
    pub fn derive_hybrid_hkdf(
        &mut self,
        classical: &ObjectRef,
        post_quantum: &ObjectRef,
        request: &HkdfRequest<'_>,
    ) -> Result<(), Error> {
        request.validate_hybrid()?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        let mut output = self.new_secret_template(
            request.id,
            request.label,
            !matches!(request.output, crate::HkdfOutput::DerivationSecret { .. }),
        )?;
        output.push(Attribute::ValueLen(
            request
                .output
                .length()
                .try_into()
                .map_err(|_| Error::InvalidParameters("HKDF output length"))?,
        ));
        let first = self.resolve(classical)?;
        let first_handle = first.handle;
        component(&first)?;
        let second = self.resolve(post_quantum)?;
        if first_handle == second.handle {
            return Err(Error::UnsupportedKeyOperation);
        }
        component(&second)?;
        let second_handle = second.handle;
        let token = self.token();
        if !token.module.raw()?.is_fn_supported(Function::DeriveKey) {
            return Err(Error::UnsupportedKeyOperation);
        }
        let advertised = token.mechanisms()?;
        for mechanism in [
            MechanismType::CONCATENATE_BASE_AND_KEY,
            MechanismType::HKDF_DERIVE,
        ] {
            if !advertised.contains(&mechanism) || !token.mechanism_info(mechanism)?.derive() {
                return Err(Error::UnsupportedKeyOperation);
            }
        }
        let intermediate = [
            Attribute::Class(crate::ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Token(false),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Derive(true),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Wrap(false),
            Attribute::Unwrap(false),
            Attribute::ValueLen(64.into()),
        ];
        let raw = self.raw()?;
        self.healthy.set(false);
        let combined = raw
            .derive_key(
                &Mechanism::ConcatenateBaseAndKey(second_handle),
                first_handle,
                &intermediate,
            )
            .map_err(|error| backend("combine hybrid secrets", error))?;
        let salt = if request.salt.is_empty() {
            HkdfSalt::Null
        } else {
            HkdfSalt::Data(request.salt)
        };
        let mechanism = Mechanism::HkdfDerive(HkdfParams::new(
            MechanismType::SHA512,
            Some(salt),
            Some(request.info),
        ));
        let outcome = raw.derive_key(&mechanism, combined, &output).map(|_| ());
        finish(outcome, raw.destroy_object(combined))?;
        self.healthy.set(true);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hybrid_profile_requires_sha512_bounded_salt_and_context() {
        let request = HkdfRequest {
            digest: DigestAlgorithm::Sha512,
            salt: &[0; 128],
            info: b"protocol v1",
            output: crate::HkdfOutput::Aes256,
            id: b"output",
            label: b"output",
        };
        assert!(request.validate_hybrid().is_ok());
        for invalid in [
            HkdfRequest {
                digest: DigestAlgorithm::Sha256,
                ..request
            },
            HkdfRequest {
                salt: &[0; 129],
                ..request
            },
            HkdfRequest {
                info: &[],
                ..request
            },
            HkdfRequest {
                info: &[0; 4097],
                ..request
            },
            HkdfRequest { id: &[], ..request },
            HkdfRequest {
                output: crate::HkdfOutput::DerivationSecret { length: 0 },
                ..request
            },
        ] {
            assert!(invalid.validate_hybrid().is_err());
        }
    }
    #[test]
    fn temporary_secret_cleanup_takes_precedence_and_preserves_the_primary_error() {
        let failed = || cryptoki::error::Error::NotSupported;
        assert!(finish(Ok(()), Ok(())).is_ok());
        assert!(matches!(
            finish(Err(failed()), Ok(())),
            Err(Error::Backend {
                operation: "derive hybrid HKDF key",
                ..
            })
        ));
        for outcome in [Ok(()), Err(failed())] {
            let primary_failed = outcome.is_err();
            match finish(outcome, Err(failed())) {
                Err(Error::HybridCleanup { primary, .. }) => {
                    assert_eq!(primary.is_some(), primary_failed)
                }
                _ => panic!("cleanup error must take precedence"),
            }
        }
    }
}
