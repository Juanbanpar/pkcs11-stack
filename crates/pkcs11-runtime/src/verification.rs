// SPDX-License-Identifier: MIT OR Apache-2.0
//! Token verification of RSA and ECDSA signatures using the same request model
//! as signing. No software verification is performed here.

use crate::{
    Attribute, AttributeType, Error, KeyCapabilities, KeyKind, Object, ObjectClass, PublicKeyRef,
    Session, SignInput, SignPlan, SignRequest, SigningMechanism, SigningPolicy,
    error::{backend, function_not_supported, map_function_not_supported},
    signing::{attribute, key_kind, mechanism, signature_input, supported_mechanism},
};
use cryptoki::{
    context::Function,
    error::{Error as NativeError, RvError},
};

/// Parameters, message/digest and raw signature for native RSA/ECDSA verification.
///
/// RSA signatures are modulus-width; ECDSA signatures use fixed-width `r || s`.
#[derive(Clone, Copy)]
pub struct VerifyRequest<'a> {
    /// Signature parameters and message/digest boundary, identical to signing.
    pub parameters: SignRequest<'a>,
    /// The signature being checked. No DER conversion is performed.
    pub signature: &'a [u8],
}

impl std::fmt::Debug for VerifyRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyRequest")
            .field("parameters", &self.parameters)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

/// Verification metadata and pure planning over the public key's permissions.
#[derive(Debug, Clone)]
pub struct VerificationCapabilities {
    planner: KeyCapabilities,
}

impl VerificationCapabilities {
    /// Observed key kind and public size/curve.
    pub fn key(&self) -> KeyKind {
        self.planner.key
    }

    /// Whether the public object permits verification.
    pub fn can_verify(&self) -> bool {
        self.planner.can_sign
    }

    /// Plan without crypto. `SigningPolicy` governs message hashing as for signing.
    pub fn plan(
        &self,
        parameters: &SignRequest<'_>,
        policy: &SigningPolicy,
    ) -> Result<SignPlan, Error> {
        self.planner
            .plan(parameters, policy)
            .map_err(|error| match error {
                Error::UnsupportedSigning(reason) => Error::UnsupportedVerification(reason),
                other => other,
            })
    }
}

fn capabilities(object: &Object<'_, '_>) -> Result<VerificationCapabilities, Error> {
    if !matches!(
        attribute(object, AttributeType::Class, true)?,
        Some(Attribute::Class(ObjectClass::PUBLIC_KEY))
    ) {
        return Err(Error::UnsupportedVerification("requires a public key"));
    }
    let key = key_kind(object).map_err(|error| match error {
        Error::UnsupportedSigning(reason) => Error::UnsupportedVerification(reason),
        other => other,
    })?;
    let can_verify = match attribute(object, AttributeType::Verify, true)? {
        Some(Attribute::Verify(enabled)) => enabled,
        _ => return Err(Error::MissingMetadata("CKA_VERIFY")),
    };
    let allowed_mechanisms = match attribute(object, AttributeType::AllowedMechanisms, false)? {
        Some(Attribute::AllowedMechanisms(value)) => Some(value),
        None => None,
        _ => return Err(Error::MissingMetadata("CKA_ALLOWED_MECHANISMS")),
    };
    let module = object.session.token().module.raw()?;
    let token = object.session.token();
    let mut mechanisms = Vec::new();
    for mechanism in token.mechanisms()? {
        if supported_mechanism(mechanism) {
            let info = token.mechanism_info(mechanism)?;
            mechanisms.push(SigningMechanism {
                mechanism,
                can_sign: info.verify()
                    && module.is_fn_supported(Function::VerifyInit)
                    && module.is_fn_supported(Function::Verify),
                minimum_bits: info.min_key_size(),
                maximum_bits: info.max_key_size(),
            });
        }
    }
    Ok(VerificationCapabilities {
        planner: KeyCapabilities {
            key,
            can_sign: can_verify,
            always_authenticate: false,
            allowed_mechanisms,
            mechanisms,
        },
    })
}

impl Session<'_> {
    /// Inspect the selected public key without verifying or changing login state.
    pub fn verification_capabilities(
        &mut self,
        key: &PublicKeyRef,
    ) -> Result<VerificationCapabilities, Error> {
        capabilities(&self.resolve(key.as_object_ref())?)
    }

    /// Verify once on the token, with the explicit hashing policy.
    ///
    /// A mismatch terminates the operation and leaves the session usable; other
    /// native failures invalidate it. No certificate is needed and successful
    /// verification makes no certificate-trust claim.
    pub fn verify(
        &mut self,
        key: &PublicKeyRef,
        request: &VerifyRequest<'_>,
        policy: &SigningPolicy,
    ) -> Result<(), Error> {
        let object = self.resolve(key.as_object_ref())?;
        let caps = capabilities(&object)?;
        let plan = caps.plan(&request.parameters, policy)?;
        let expected = match caps.key() {
            KeyKind::Rsa { bits } => bits.div_ceil(8),
            KeyKind::Ec(curve) => 2 * curve.bits().div_ceil(8),
            KeyKind::Edwards(curve) => curve.signature_length(),
        };
        if request.signature.len() != expected {
            return Err(Error::SignatureMismatch);
        }
        let data = signature_input(&request.parameters, plan.hash_location());
        let mechanism = mechanism(
            &request.parameters,
            plan.hash_location() == crate::HashLocation::Token,
        )?;
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        match raw.verify(&mechanism, object.handle, &data, request.signature) {
            Ok(()) => {
                object.session.healthy.set(true);
                Ok(())
            }
            Err(NativeError::Pkcs11(
                RvError::SignatureInvalid | RvError::SignatureLenRange,
                Function::Verify,
            )) => {
                object.session.healthy.set(true);
                Err(Error::SignatureMismatch)
            }
            Err(error) => {
                if function_not_supported(&error) {
                    object.session.healthy.set(true);
                }
                Err(map_function_not_supported(
                    backend("verify", error),
                    Error::UnsupportedVerification("verification unavailable"),
                ))
            }
        }
    }

    /// Verify a signature over a precomputed digest using the signature-first
    /// `C_VerifySignatureInit` interface.
    ///
    /// The caller must provide a digest of exactly the selected length and a
    /// signature of the expected width. A mismatch leaves the session usable.
    pub fn verify_signature(
        &mut self,
        key: &PublicKeyRef,
        request: &SignRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        let object = self.resolve(key.as_object_ref())?;
        let caps = capabilities(&object)?;
        let SignInput::Digest(digest) = request.input else {
            return Err(Error::InvalidParameters(
                "signature-first verification requires a digest",
            ));
        };
        if digest.len() != request.digest.output_len() {
            return Err(Error::InvalidParameters("digest length"));
        }
        let expected = match caps.key() {
            KeyKind::Rsa { bits } => bits.div_ceil(8),
            KeyKind::Ec(curve) => 2 * curve.bits().div_ceil(8),
            KeyKind::Edwards(curve) => curve.signature_length(),
        };
        if signature.len() != expected {
            return Err(Error::SignatureMismatch);
        }
        let module = object.session.token().module.raw()?;
        if !module.is_fn_supported(Function::VerifySignatureInit)
            || !module.is_fn_supported(Function::VerifySignature)
        {
            return Err(Error::UnsupportedVerification(
                "signature-first verification unavailable",
            ));
        }
        let raw = object.session.raw()?;
        let mechanism = mechanism(request, false)?;
        let data = signature_input(request, crate::HashLocation::Caller);
        object.session.healthy.set(false);
        match (|| {
            raw.verify_signature_init(&mechanism, object.handle, signature)?;
            raw.verify_signature(&data)
        })() {
            Ok(()) => {
                object.session.healthy.set(true);
                Ok(())
            }
            Err(NativeError::Pkcs11(RvError::SignatureInvalid | RvError::SignatureLenRange, _)) => {
                object.session.healthy.set(true);
                Err(Error::SignatureMismatch)
            }
            Err(error) => {
                if function_not_supported(&error) {
                    object.session.healthy.set(true);
                }
                Err(map_function_not_supported(
                    backend("signature-first verify", error),
                    Error::UnsupportedVerification("signature-first verification unavailable"),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_request_debug_omits_signature() {
        let request = VerifyRequest {
            parameters: SignRequest {
                algorithm: crate::SignatureAlgorithm::Ecdsa,
                digest: crate::DigestAlgorithm::Sha256,
                input: SignInput::Digest(&[0; 32]),
                pss: None,
            },
            signature: b"canary",
        };
        assert!(!format!("{request:?}").contains("canary"));
    }
}
