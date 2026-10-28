//! EdDSA mechanism types

use cryptoki_sys::*;
use std::{convert::TryInto, marker::PhantomData, ptr::null_mut};

/// EdDSA signature schemes.
///
/// The EdDSA mechanism, denoted CKM_EDDSA, is a mechanism for
/// single-part and multipart signatures and verification for
/// EdDSA.  This mechanism implements the five EdDSA signature
/// schemes defined in RFC 8032 and RFC 8410.
///
/// For curves according to RFC 8032, this mechanism has an
/// optional parameter, a CK_EDDSA_PARAMS structure.
///
/// | Signature Scheme | Mechanism Param | phFlag | Context Data |
/// |------------------|-----------------|--------|--------------|
/// | Ed25519          | Not Required    | N/A    | N/A          |
/// | Ed25519ctx       | Required        | False  | Optional     |
/// | Ed25519ph        | Required        | True   | Optional     |
/// | Ed448            | Required        | False  | Optional     |
/// | Ed448ph          | Required        | True   | Optional     |
///
/// The absence or presence of the parameter as well as its
/// content is used to identify which signature scheme is to be
/// used.
#[derive(Debug, Clone, Copy)]
pub enum EddsaSignatureScheme<'a> {
    /// Pure EdDSA mode where the scheme is implicitly defined
    /// by the curve.
    Pure,
    /// Ed25519 signature scheme without additional parameters.
    Ed25519,
    /// Ed25519 signature scheme with optional context-specific
    /// data.
    Ed25519ctx(&'a [u8]),
    /// Ed25519 signature scheme with pre-hashing and optional
    /// context-specific data.
    Ed25519ph(&'a [u8]),
    /// Ed448 signature scheme with optional context-specific data.
    Ed448(&'a [u8]),
    /// Ed448 signature scheme with pre-hashing and optional
    /// context-specific data.
    Ed448ph(&'a [u8]),
}

/// EdDSA parameters.
///
/// The EdDSA mechanism, denoted CKM_EDDSA, is a mechanism for
/// single-part and multipart signatures and verification for
/// EdDSA. This mechanism implements the five EdDSA signature
/// schemes defined in RFC 8032 and RFC 8410.
///
/// For curves according to RFC 8032, this mechanism has an
/// optional parameter, a CK_EDDSA_PARAMS structure.
///
/// The absence or presence of the parameter as well as its
/// content is used to identify which signature scheme is to be
/// used.
///
/// | Signature Scheme | Mechanism Param | phFlag | Context Data |
/// |------------------|-----------------|--------|--------------|
/// | Ed25519          | Not Required    | N/A    | N/A          |
/// | Ed25519ctx       | Required        | False  | Optional     |
/// | Ed25519ph        | Required        | True   | Optional     |
/// | Ed448            | Required        | False  | Optional     |
/// | Ed448ph          | Required        | True   | Optional     |
///
/// This structure wraps a `CK_EDDSA_PARAMS` structure.
#[derive(Copy, Debug, Clone)]
#[repr(transparent)]
pub struct EddsaParams<'a> {
    inner: Option<CK_EDDSA_PARAMS>,
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> EddsaParams<'a> {
    /// Construct EdDSA parameters.
    ///
    /// # Arguments
    ///
    /// * `scheme` - The EdDSA signature scheme.
    ///
    /// # Returns
    ///
    /// A new EddsaParams struct.
    pub fn new(scheme: EddsaSignatureScheme<'a>) -> Self {
        let params =
            match scheme {
                EddsaSignatureScheme::Pure | EddsaSignatureScheme::Ed25519 => None,
                EddsaSignatureScheme::Ed25519ctx(context)
                | EddsaSignatureScheme::Ed448(context) => Some({
                    CK_EDDSA_PARAMS {
                        phFlag: false.into(),
                        pContextData: if context.is_empty() {
                            null_mut()
                        } else {
                            context.as_ptr() as *mut _
                        },
                        ulContextDataLen: context
                            .len()
                            .try_into()
                            .expect("usize can not fit in CK_ULONG"),
                    }
                }),
                EddsaSignatureScheme::Ed25519ph(context)
                | EddsaSignatureScheme::Ed448ph(context) => Some({
                    CK_EDDSA_PARAMS {
                        phFlag: true.into(),
                        pContextData: if context.is_empty() {
                            null_mut()
                        } else {
                            context.as_ptr() as *mut _
                        },
                        ulContextDataLen: context
                            .len()
                            .try_into()
                            .expect("usize can not fit in CK_ULONG"),
                    }
                }),
            };

        Self {
            inner: params,
            _marker: PhantomData,
        }
    }

    /// Retrieve the inner `CK_EDDSA_PARAMS` struct, if present.
    ///
    /// This method provides a reference to the `CK_EDDSA_PARAMS`
    /// struct encapsulated within the `EddsaParams`, if the signature
    /// scheme requires additional parameters.
    ///
    /// # Returns
    ///
    /// `Some(&CK_EDDSA_PARAMS)` if the signature scheme has associated
    /// parameters, otherwise `None`.
    pub fn inner(&self) -> Option<&CK_EDDSA_PARAMS> {
        self.inner.as_ref()
    }
}
