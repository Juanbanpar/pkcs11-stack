// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AesKeySize, Attribute, DigestAlgorithm, Error, KeyOperation, KeyOperationProfile, NamedCurve,
    ObjectRef, Session,
    key_operations::{profile, validate_secret_identity},
};
use cryptoki::{
    context::Function,
    mechanism::{
        Mechanism,
        elliptic_curve::{EcKdf, Ecdh1DeriveParams},
    },
};

/// Explicit ECDH key derivation function. Provider parameter support is advisory
/// until C_DeriveKey completes; no fallback to another KDF is attempted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdhKdf {
    /// No KDF: preserve the complete raw shared secret for a later KDF.
    Null,
    /// ANSI X9.63 with SHA-256/384/512: Hash(Z || counter || shared info).
    /// The counter is big-endian.
    X963(DigestAlgorithm),
    /// NIST SP 800-56A with SHA-256/384/512: Hash(counter || Z || shared info).
    Sp80056a(DigestAlgorithm),
}
impl EcdhKdf {
    fn parameters(self, info: &[u8]) -> EcKdf<'_> {
        match self {
            Self::Null => EcKdf::null(),
            Self::X963(DigestAlgorithm::Sha224) => EcKdf::sha224(info),
            Self::X963(DigestAlgorithm::Sha256) => EcKdf::sha256(info),
            Self::X963(DigestAlgorithm::Sha384) => EcKdf::sha384(info),
            Self::X963(DigestAlgorithm::Sha512) => EcKdf::sha512(info),
            Self::Sp80056a(DigestAlgorithm::Sha224) => EcKdf::sha224_sp800(info),
            Self::Sp80056a(DigestAlgorithm::Sha256) => EcKdf::sha256_sp800(info),
            Self::Sp80056a(DigestAlgorithm::Sha384) => EcKdf::sha384_sp800(info),
            Self::Sp80056a(DigestAlgorithm::Sha512) => EcKdf::sha512_sp800(info),
        }
    }
}
/// Type, length and permissions of an ECDH output key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdhOutput {
    /// Complete field-width generic secret, with derivation permission only.
    /// Requires the null KDF; it is never silently truncated into an AES key.
    RawSecret,
    /// Generic secret, with derivation permission only. Requires a SHA-2 KDF.
    DerivationSecret {
        /// Requested length, from 1 through 4096 bytes.
        length: usize,
    },
    /// AES encryption/decryption key. Requires a SHA-2 KDF.
    Aes(AesKeySize),
}
impl EcdhOutput {
    /// Output length in bytes for the chosen curve.
    pub fn length(self, curve: NamedCurve) -> usize {
        match self {
            Self::RawSecret => match curve {
                NamedCurve::P256 => 32,
                NamedCurve::P384 => 48,
                NamedCurve::P521 => 66,
            },
            Self::DerivationSecret { length } => length,
            Self::Aes(size) => size.length(),
        }
    }
}
/// Bounded ECDH derivation request. No private/secret bytes cross this API.
/// Outputs are persistent, private, sensitive and nonextractable.
#[derive(Clone, Copy)]
pub struct EcdhKeyRequest<'a> {
    /// Named curve shared by base and peer.
    pub curve: NamedCurve,
    /// Uncompressed SEC1 point, which the caller must validate on the chosen curve.
    pub peer: &'a [u8],
    /// Explicit KDF, never changed after a provider rejection.
    pub kdf: EcdhKdf,
    /// Public protocol context, at most 4096 bytes; empty for the null KDF.
    pub shared_info: &'a [u8],
    /// Output type, permissions and length.
    pub output: EcdhOutput,
    /// Nonempty new secret ID, at most 128 bytes; duplicate IDs are rejected.
    pub id: &'a [u8],
    /// Nonempty label, at most 128 bytes.
    pub label: &'a [u8],
}
impl std::fmt::Debug for EcdhKeyRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdhKeyRequest")
            .field("curve", &self.curve)
            .field("kdf", &self.kdf)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}
impl EcdhKeyRequest<'_> {
    /// Validate shape, identity and size bounds without provider calls. Point
    /// membership must be checked by the caller; pkcs11-client validates SPKI input.
    pub fn validate(&self) -> Result<(), Error> {
        if matches!(
            self.kdf,
            EcdhKdf::X963(DigestAlgorithm::Sha224) | EcdhKdf::Sp80056a(DigestAlgorithm::Sha224)
        ) {
            return Err(Error::InvalidParameters("ECDH digest"));
        }
        validate_secret_identity(self.id, self.label)?;
        let point_length = match self.curve {
            NamedCurve::P256 => 65,
            NamedCurve::P384 => 97,
            NamedCurve::P521 => 133,
        };
        if self.peer.first() != Some(&4) || self.peer.len() != point_length {
            return Err(Error::InvalidParameters("ECDH peer"));
        }
        if self.shared_info.len() > 4096
            || !(1..=4096).contains(&self.output.length(self.curve))
            || (self.kdf == EcdhKdf::Null) != (self.output == EcdhOutput::RawSecret)
            || (self.kdf == EcdhKdf::Null && !self.shared_info.is_empty())
        {
            return Err(Error::InvalidParameters("ECDH KDF or output"));
        }
        Ok(())
    }
}
impl Session<'_> {
    /// Derive one persistent key with explicit KDF, shared info, output length and
    /// purpose. Requires RW access, CKA_DERIVE, matching curve and allowed mechanism.
    /// Always-authenticate bases are unsupported. No key bytes leave the token.
    /// Failures may leave an object or discard the session; no retry or rollback.
    pub fn derive_ecdh_key(
        &mut self,
        base: &ObjectRef,
        request: &EcdhKeyRequest<'_>,
    ) -> Result<(), Error> {
        request.validate()?;
        let mut template = self.new_secret_template(
            request.id,
            request.label,
            matches!(request.output, EcdhOutput::Aes(_)),
        )?;
        template.push(Attribute::ValueLen(
            request
                .output
                .length(request.curve)
                .try_into()
                .map_err(|_| Error::InvalidParameters("ECDH output length"))?,
        ));
        let object = self.resolve(base)?;
        if profile(&object, KeyOperation::Derive)? != KeyOperationProfile::EcdhRaw(request.curve)
            || !object
                .session
                .token()
                .module
                .raw()?
                .is_fn_supported(Function::DeriveKey)
        {
            return Err(Error::UnsupportedKeyOperation);
        }
        let mechanism = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(
            request.kdf.parameters(request.shared_info),
            request.peer,
        ));
        object.session.write_operation("derive ECDH key", |raw| {
            raw.derive_key(&mechanism, object.handle, &template)
        })?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn null_kdf_preserves_full_width_and_rejects_context_or_purposed_output() {
        let mut point = [0; 133];
        point[0] = 4;
        let raw = EcdhKeyRequest {
            curve: NamedCurve::P521,
            peer: &point,
            kdf: EcdhKdf::Null,
            shared_info: &[],
            output: EcdhOutput::RawSecret,
            id: b"key",
            label: b"label",
        };
        raw.validate().unwrap();
        assert_eq!(raw.output.length(raw.curve), 66);
        for output in [
            EcdhOutput::Aes(AesKeySize::Bits256),
            EcdhOutput::DerivationSecret { length: 64 },
        ] {
            assert!(EcdhKeyRequest { output, ..raw }.validate().is_err());
        }
        assert!(
            EcdhKeyRequest {
                shared_info: b"context",
                ..raw
            }
            .validate()
            .is_err()
        );
        let hashed = EcdhKeyRequest {
            kdf: EcdhKdf::X963(DigestAlgorithm::Sha512),
            output: EcdhOutput::DerivationSecret { length: 64 },
            ..raw
        };
        hashed.validate().unwrap();
        for length in [0, 4097, usize::MAX] {
            assert!(
                EcdhKeyRequest {
                    output: EcdhOutput::DerivationSecret { length },
                    ..hashed
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            EcdhKeyRequest {
                shared_info: &[0; 4097],
                ..hashed
            }
            .validate()
            .is_err()
        );
        assert!(
            EcdhKeyRequest {
                output: EcdhOutput::RawSecret,
                ..hashed
            }
            .validate()
            .is_err()
        );
    }
}
