// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, Object, error::backend};
use cryptoki::{
    context::Function,
    error::{Error as NativeError, RvError},
    mechanism::Mechanism,
};

pub(crate) fn generate_into(
    object: &Object<'_, '_>,
    mechanism: &Mechanism<'_>,
    message: &[u8],
    tag: &mut [u8],
) -> Result<(), Error> {
    let raw = object.session.raw()?;
    object.session.healthy.set(false);
    raw.sign_init(mechanism, object.handle)
        .map_err(|e| backend("MAC init", e))?;
    let written = raw
        .sign_initialized_into(message, tag)
        .map_err(|e| backend("MAC", e))?;
    if written != tag.len() {
        return Err(Error::InvalidKeyOutput);
    }
    object.session.healthy.set(true);
    Ok(())
}
pub(crate) fn verify(
    object: &Object<'_, '_>,
    mechanism: &Mechanism<'_>,
    message: &[u8],
    tag: &[u8],
) -> Result<(), Error> {
    let raw = object.session.raw()?;
    object.session.healthy.set(false);
    match raw.verify(mechanism, object.handle, message, tag) {
        Ok(()) => {
            object.session.healthy.set(true);
            Ok(())
        }
        Err(NativeError::Pkcs11(
            RvError::SignatureInvalid | RvError::SignatureLenRange,
            Function::Verify,
        )) => {
            object.session.healthy.set(true);
            Err(Error::MacMismatch)
        }
        Err(error) => Err(backend("MAC verify", error)),
    }
}
