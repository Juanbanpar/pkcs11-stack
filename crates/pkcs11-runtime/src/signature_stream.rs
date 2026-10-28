// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    CancelFlags, DigestAlgorithm, Error, HashLocation, KeyCapabilities, KeyKind, MechanismType,
    Object, Pin, PrivateKeyRef, PssParameters, PublicKeyRef, Session, SignInput, SignPlan,
    SignRequest, SignatureAlgorithm, SigningPolicy, VerificationCapabilities,
    error::backend,
    signing::{mechanism, signature_input},
};
use cryptoki::{
    context::{Function, Pkcs11},
    error::{Error as NativeError, RvError},
    session::UserType,
};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, digest::DynDigest};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::cell::Cell;

/// Owned parameters for a typed signing or verification request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureParameters {
    /// Signature family.
    pub algorithm: SignatureAlgorithm,
    /// SHA-2 or SHA-3 message digest.
    pub digest: DigestAlgorithm,
    /// Explicit PSS parameters; absent for other families.
    pub pss: Option<PssParameters>,
}
impl SignatureParameters {
    /// Borrow input without retaining its bytes.
    pub fn request(self, input: SignInput<'_>) -> SignRequest<'_> {
        SignRequest {
            algorithm: self.algorithm,
            digest: self.digest,
            pss: self.pss,
            input,
        }
    }
}

/// Maximum classical streaming signature size: RSA up to 8192 bits or a supported
/// named EC curve. This bound does not change existing single-part APIs.
pub const CLASSICAL_SIGNATURE_MAXIMUM_LENGTH: usize = 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Direction {
    Sign,
    Verify,
}
impl Direction {
    pub(crate) fn supported(self, module: &Pkcs11, mechanism: MechanismType) -> bool {
        let raw = matches!(
            mechanism,
            MechanismType::RSA_PKCS | MechanismType::RSA_PKCS_PSS | MechanismType::ECDSA
        );
        let functions: &[Function] = match (self, raw) {
            (Self::Sign, true) => &[Function::SignInit, Function::Sign],
            (Self::Verify, true) => &[Function::VerifyInit, Function::Verify],
            (Self::Sign, false) => &[
                Function::SignInit,
                Function::SignUpdate,
                Function::SignFinal,
            ],
            (Self::Verify, false) => &[
                Function::VerifyInit,
                Function::VerifyUpdate,
                Function::VerifyFinal,
            ],
        };
        functions.iter().all(|&f| module.is_fn_supported(f))
    }
    fn unsupported(self, reason: &'static str) -> Error {
        match self {
            Self::Sign => Error::UnsupportedSigning(reason),
            Self::Verify => Error::UnsupportedVerification(reason),
        }
    }
}
fn signature_length(key: KeyKind, direction: Direction) -> Result<usize, Error> {
    let length = match key {
        KeyKind::Rsa { bits } => bits.div_ceil(8),
        KeyKind::Ec(curve) => 2 * curve.bits().div_ceil(8),
    };
    if !(1..=CLASSICAL_SIGNATURE_MAXIMUM_LENGTH).contains(&length) {
        return Err(direction.unsupported("streaming signature length"));
    }
    Ok(length)
}
fn hasher(algorithm: DigestAlgorithm) -> Box<dyn DynDigest> {
    match algorithm {
        DigestAlgorithm::Sha224 => Box::new(Sha224::new()),
        DigestAlgorithm::Sha256 => Box::new(Sha256::new()),
        DigestAlgorithm::Sha384 => Box::new(Sha384::new()),
        DigestAlgorithm::Sha512 => Box::new(Sha512::new()),
        DigestAlgorithm::Sha3_224 => Box::new(Sha3_224::new()),
        DigestAlgorithm::Sha3_256 => Box::new(Sha3_256::new()),
        DigestAlgorithm::Sha3_384 => Box::new(Sha3_384::new()),
        DigestAlgorithm::Sha3_512 => Box::new(Sha3_512::new()),
    }
}
/// Exclusive RSA/ECDSA message-signing guard. Holds only native operation state
/// and, when policy permits software hashing, incremental hash state. Drop before
/// successful finish or confirmed cancellation discards the session.
#[derive(Debug)]
pub struct SigningOperation<'a>(State<'a>);
/// Exclusive RSA/ECDSA message-verification guard. Completion uses the public
/// key's independent verification permission; drop discards incomplete sessions.
#[derive(Debug)]
pub struct VerificationOperation<'a>(State<'a>);
struct State<'a> {
    raw: &'a cryptoki::session::Session,
    healthy: &'a Cell<bool>,
    parameters: SignatureParameters,
    plan: SignPlan,
    direction: Direction,
    length: usize,
    hash: Option<Box<dyn DynDigest>>,
    active: bool,
    cancellation_supported: bool,
}
impl std::fmt::Debug for State<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureOperation")
            .field("parameters", &self.parameters)
            .field("plan", &self.plan)
            .finish_non_exhaustive()
    }
}
impl Drop for State<'_> {
    fn drop(&mut self) {
        if self.active {
            self.healthy.set(false);
        }
    }
}
impl<'a> State<'a> {
    fn start(
        object: &Object<'a, '_>,
        parameters: SignatureParameters,
        plan: SignPlan,
        length: usize,
        direction: Direction,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Self, Error> {
        let pin = if plan.context_authentication() {
            object
                .session
                .login_pin(context_pin.ok_or(Error::ContextAuthenticationRequired)?)?
        } else {
            if context_pin.is_some() {
                return Err(Error::InvalidParameters(
                    "context PIN for a key without always-authenticate",
                ));
            }
            None
        };
        let hash =
            (plan.hash_location() == HashLocation::Software).then(|| hasher(parameters.digest));
        let mechanism = mechanism(
            &parameters.request(SignInput::Message(&[])),
            plan.hash_location() == HashLocation::Token,
        )?;
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        match direction {
            Direction::Sign => raw.sign_init(&mechanism, object.handle),
            Direction::Verify => raw.verify_init(&mechanism, object.handle),
        }
        .map_err(|e| backend("initialize streaming signature", e))?;
        if plan.context_authentication() {
            raw.login(UserType::ContextSpecific, pin)
                .map_err(|e| backend("context login", e))?;
        }
        Ok(Self {
            raw,
            healthy: &object.session.healthy,
            parameters,
            plan,
            direction,
            length,
            hash,
            active: true,
            cancellation_supported: object
                .session
                .token()
                .module
                .supports_function(Function::SessionCancel),
        })
    }
    fn check_active(&self) -> Result<(), Error> {
        if self.active {
            Ok(())
        } else {
            Err(Error::Closed)
        }
    }
    fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.check_active()?;
        if let Some(hash) = &mut self.hash {
            hash.update(bytes);
            return Ok(());
        }
        let result = match self.direction {
            Direction::Sign => self.raw.sign_update(bytes),
            Direction::Verify => self.raw.verify_update(bytes),
        };
        if let Err(error) = result {
            self.active = false;
            return Err(backend("update signature", error));
        }
        Ok(())
    }
    fn cancel(mut self) -> Result<(), Error> {
        self.check_active()?;
        let flags = match self.direction {
            Direction::Sign => CancelFlags::SIGN,
            Direction::Verify => CancelFlags::VERIFY,
        };
        crate::cancellation::cancel(self.raw, self.cancellation_supported, flags)?;
        self.active = false;
        self.healthy.set(true);
        Ok(())
    }
    fn complete(&mut self) {
        self.active = false;
        self.healthy.set(true);
    }
}
impl SigningOperation<'_> {
    /// Inspect the selected mechanism, hashing boundary and context requirement.
    pub fn plan(&self) -> &SignPlan {
        &self.0.plan
    }
    /// Process a message chunk, including empty input. No total input limit is
    /// imposed; callers enforce their budget. Native failures prevent further use.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.0.update(bytes)
    }
    /// Cancel once; only confirmed native termination restores reuse. No implicit
    /// cancellation or retry occurs, and failed updates cannot be repaired.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
    /// Complete once into bounded storage without length queries or retries.
    /// RSA output is modulus-width; ECDSA is fixed-width r || s. Malformed output
    /// discards the session. Check closure before publishing the signature.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        self.0.check_active()?;
        let mut output = vec![0; self.0.length];
        let result = if let Some(hash) = self.0.hash.take() {
            let digest = hash.finalize();
            let request = self.0.parameters.request(SignInput::Digest(&digest));
            let input = signature_input(&request, HashLocation::Caller);
            self.0.raw.sign_initialized_into(&input, &mut output)
        } else {
            self.0.raw.sign_final_into(&mut output)
        };
        let written = result.map_err(|e| backend("finish signature", e))?;
        if written != output.len() {
            return Err(Error::InvalidSignature);
        }
        self.0.complete();
        Ok(output)
    }
}
impl VerificationOperation<'_> {
    /// Inspect the selected mechanism and hashing boundary.
    pub fn plan(&self) -> &SignPlan {
        &self.0.plan
    }
    /// Process a message chunk, including empty input. Callers enforce their input
    /// budget. Native failure prevents further use and requires session closure.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.0.update(bytes)
    }
    /// Cancel once; only confirmed native termination restores reuse. No implicit
    /// cancellation or retry occurs, and failed updates cannot be repaired.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
    /// Verify once. Completed length/content mismatches permit reuse and return
    /// SignatureMismatch; other native failures discard the session. RSA signatures
    /// are modulus-width; ECDSA uses fixed-width r || s, without DER conversion.
    pub fn finish(mut self, signature: &[u8]) -> Result<(), Error> {
        self.0.check_active()?;
        let result = if let Some(hash) = self.0.hash.take() {
            let digest = hash.finalize();
            let request = self.0.parameters.request(SignInput::Digest(&digest));
            let input = signature_input(&request, HashLocation::Caller);
            self.0.raw.verify_initialized(&input, signature)
        } else {
            self.0.raw.verify_final(signature)
        };
        let result = match result {
            Ok(()) if signature.len() == self.0.length => Ok(()),
            Ok(())
            | Err(NativeError::Pkcs11(
                RvError::SignatureInvalid | RvError::SignatureLenRange,
                Function::Verify | Function::VerifyFinal,
            )) => Err(Error::SignatureMismatch),
            Err(error) => return Err(backend("finish signature verification", error)),
        };
        self.0.complete();
        result
    }
}
impl Session<'_> {
    /// Discover streaming RSA/ECDSA choices. Combined mechanisms require multipart
    /// entry points; raw mechanisms require single-part completion after incremental
    /// software hashing. Key permissions, allowed mechanisms and policy still apply.
    pub fn streaming_key_capabilities(
        &mut self,
        key: &PrivateKeyRef,
    ) -> Result<KeyCapabilities, Error> {
        let object = self.resolve(key.as_object_ref())?;
        let caps = crate::signing::capabilities(&object, true)?;
        signature_length(caps.key, Direction::Sign)?;
        Ok(caps)
    }
    /// Discover streaming verification choices using only public-key verification
    /// permissions and native entry points. The output-size bound also applies.
    pub fn streaming_verification_capabilities(
        &mut self,
        key: &PublicKeyRef,
    ) -> Result<VerificationCapabilities, Error> {
        let caps = crate::verification::capabilities(&self.resolve(key.as_object_ref())?, true)?;
        signature_length(caps.key(), Direction::Verify)?;
        Ok(caps)
    }
    /// Begin exclusive RSA/ECDSA message signing. Context login occurs after init
    /// and before any native update. PINs are borrowed only for this call. Hashing
    /// policy is resolved before init; no later fallback, retry or whole-input
    /// buffering occurs. Drop discards incomplete sessions. Output is at most 1024
    /// bytes; streaming input has no total limit. Existing single-part APIs remain.
    pub fn start_signing(
        &mut self,
        key: &PrivateKeyRef,
        parameters: SignatureParameters,
        policy: &SigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<SigningOperation<'_>, Error> {
        let object = self.resolve(key.as_object_ref())?;
        let live = crate::signing::capabilities(&object, true)?;
        let plan = live.plan(&parameters.request(SignInput::Message(&[])), policy)?;
        let length = signature_length(live.key, Direction::Sign)?;
        Ok(SigningOperation(State::start(
            &object,
            parameters,
            plan,
            length,
            Direction::Sign,
            context_pin,
        )?))
    }
    /// Begin exclusive RSA/ECDSA message verification. Policy controls hashing
    /// exactly as for signing. Drop/read/update failures discard incomplete sessions;
    /// only completed mismatches or confirmed cancellation restore session reuse.
    pub fn start_verification(
        &mut self,
        key: &PublicKeyRef,
        parameters: SignatureParameters,
        policy: &SigningPolicy,
    ) -> Result<VerificationOperation<'_>, Error> {
        let object = self.resolve(key.as_object_ref())?;
        let caps = crate::verification::capabilities(&object, true)?;
        let plan = caps.plan(&parameters.request(SignInput::Message(&[])), policy)?;
        let length = signature_length(caps.key(), Direction::Verify)?;
        Ok(VerificationOperation(State::start(
            &object,
            parameters,
            plan,
            length,
            Direction::Verify,
            None,
        )?))
    }
}
