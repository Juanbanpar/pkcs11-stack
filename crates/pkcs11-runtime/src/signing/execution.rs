// SPDX-License-Identifier: MIT OR Apache-2.0
use std::borrow::Cow;

use cryptoki::session::UserType;

use crate::{Error, KeyKind, Pin, PrivateKeyRef, Session, error::backend};

use super::{
    HashLocation, SignInput, SignRequest, SignatureAlgorithm, SigningPolicy,
    capabilities::capabilities, planning::mechanism, rsa,
};

pub(super) fn signature_input<'a>(
    request: &SignRequest<'a>,
    hashing: HashLocation,
) -> Cow<'a, [u8]> {
    let mut data = match request.input {
        SignInput::Message(value) if hashing == HashLocation::Software => {
            Cow::Owned(request.digest.hash(value))
        }
        SignInput::Message(value) | SignInput::Digest(value) => Cow::Borrowed(value),
    };
    if hashing != HashLocation::Token && request.algorithm == SignatureAlgorithm::RsaPkcs1 {
        data = Cow::Owned(rsa::digest_info(request.digest, &data));
    }
    data
}

impl Session<'_> {
    /// Resolve, rediscover, plan and sign once. No operation is transparently retried.
    ///
    /// Backend failures discard this session from a pool. Context-specific PINs
    /// are borrowed only for this call. Output is RSA bytes or fixed-width ECDSA r || s.
    pub fn sign(
        &mut self,
        key: &PrivateKeyRef,
        request: &SignRequest<'_>,
        policy: &SigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        let result = self.sign_once(key, request, policy, context_pin);
        if matches!(
            &result,
            Err(Error::Backend { .. } | Error::TokenChanged | Error::InvalidSignature)
        ) {
            self.healthy.set(false);
        }
        result
    }
    fn sign_once(
        &mut self,
        key: &PrivateKeyRef,
        request: &SignRequest<'_>,
        policy: &SigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        let object = self.resolve(key.as_object_ref())?;
        let capabilities = capabilities(&object)?;
        let plan = capabilities.plan(request, policy)?;
        let pin = object
            .session
            .prepare_context_pin(plan.context_authentication(), context_pin)?;
        let data = signature_input(request, plan.hash_location());
        let mechanism = mechanism(request, plan.hash_location() == HashLocation::Token)?;
        let raw = object.session.begin_operation()?;
        let signature = if plan.context_authentication() {
            raw.sign_init(&mechanism, object.handle)
                .map_err(|e| backend("sign init", e))?;
            crate::session::login_with_pin(raw, UserType::ContextSpecific, pin)
                .map_err(|e| backend("context login", e))?;
            raw.sign_update(&data)
                .map_err(|e| backend("sign update", e))?;
            raw.sign_final().map_err(|e| backend("sign final", e))?
        } else {
            raw.sign(&mechanism, object.handle, &data)
                .map_err(|e| backend("sign", e))?
        };
        let expected = match capabilities.key {
            KeyKind::Rsa { bits } => bits.div_ceil(8),
            KeyKind::Ec(curve) => 2 * curve.bits().div_ceil(8),
            KeyKind::Edwards(curve) => curve.signature_length(),
            KeyKind::Montgomery(_) => 0,
        };
        if signature.len() != expected {
            return Err(Error::InvalidSignature);
        }
        object.session.healthy.set(true);
        Ok(signature)
    }
}
