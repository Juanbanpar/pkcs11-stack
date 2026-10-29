// SPDX-License-Identifier: Apache-2.0
//! Structural inspection of attribute templates without retrieving leaf values.
use super::Session;
use crate::{
    context::Function,
    error::{Error, Result, Rv, RvError},
    object::{AttributeInfo, ObjectHandle},
};
use cryptoki_sys::*;
use std::{mem::size_of, ptr};

/// Maximum number of nested templates, including the requested root.
pub const TEMPLATE_METADATA_MAX_DEPTH: usize = 4;
/// Maximum total number of entries across the requested template tree.
pub const TEMPLATE_METADATA_MAX_MEMBERS: usize = 128;
/// Maximum total native array storage; leaf values are never allocated.
pub const TEMPLATE_METADATA_MAX_BYTES: usize = 65_536;

/// Standard attributes whose values contain `CK_ATTRIBUTE` arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateAttribute {
    /// Constraints on keys wrapped with this key.
    Wrap,
    /// Constraints on keys unwrapped with this key.
    Unwrap,
    /// Constraints on keys derived from this key.
    Derive,
}
impl TemplateAttribute {
    /// Native attribute ID, including `CKF_ARRAY_ATTRIBUTE`.
    #[allow(clippy::useless_conversion)]
    pub fn id(self) -> u64 {
        self.native().into()
    }
    fn native(self) -> CK_ATTRIBUTE_TYPE {
        match self {
            Self::Wrap => CKA_WRAP_TEMPLATE,
            Self::Unwrap => CKA_UNWRAP_TEMPLATE,
            Self::Derive => CKA_DERIVE_TEMPLATE,
        }
    }
    fn from_native(id: CK_ATTRIBUTE_TYPE) -> Option<Self> {
        match id {
            CKA_WRAP_TEMPLATE => Some(Self::Wrap),
            CKA_UNWRAP_TEMPLATE => Some(Self::Unwrap),
            CKA_DERIVE_TEMPLATE => Some(Self::Derive),
            _ => None,
        }
    }
}

/// One template entry's type, length and optional nested structure.
/// No leaf value is requested, including public values. Unknown IDs and other
/// array types (such as `CKA_ALLOWED_MECHANISMS`) remain opaque.
#[derive(Debug, Clone)]
pub struct TemplateMember {
    /// Native-width attribute ID, preserved without interpretation.
    pub attribute_type: u64,
    /// Available byte length, or unavailable. A nested unavailable length cannot
    /// distinguish sensitive from invalid: the native return code is shared by
    /// the whole request, and must not be attributed to an individual member.
    pub status: AttributeInfo,
    /// Present only for readable wrap/unwrap/derive template members.
    pub template: Option<Vec<TemplateMember>>,
}

/// Bounded structural metadata for a single standard template attribute.
#[derive(Debug, Clone)]
pub struct TemplateMetadata {
    /// Requested template attribute.
    pub kind: TemplateAttribute,
    /// Root availability; sensitive and invalid roots retain their native status.
    pub status: AttributeInfo,
    /// Entries in provider order. Empty for an unavailable or empty template.
    pub members: Vec<TemplateMember>,
}

#[derive(Default)]
struct Budget {
    members: usize,
    bytes: usize,
}
struct Array {
    native: Vec<CK_ATTRIBUTE>,
    children: Vec<Option<Array>>,
    observed: Option<Vec<(CK_ATTRIBUTE_TYPE, CK_ULONG)>>,
}
impl Array {
    fn new(length: usize, depth: usize, budget: &mut Budget) -> Result<Self> {
        if depth > TEMPLATE_METADATA_MAX_DEPTH || length % size_of::<CK_ATTRIBUTE>() != 0 {
            return Err(Error::InvalidValue);
        }
        let count = length / size_of::<CK_ATTRIBUTE>();
        budget.members = budget
            .members
            .checked_add(count)
            .ok_or(Error::InvalidValue)?;
        budget.bytes = budget
            .bytes
            .checked_add(length)
            .ok_or(Error::InvalidValue)?;
        if budget.members > TEMPLATE_METADATA_MAX_MEMBERS
            || budget.bytes > TEMPLATE_METADATA_MAX_BYTES
        {
            return Err(Error::InvalidValue);
        }
        // Typed storage supplies CK_ATTRIBUTE alignment and initializes every
        // pointer before the provider sees it (PKCS #11 section 5.7.5).
        Ok(Self {
            native: vec![
                CK_ATTRIBUTE {
                    type_: 0,
                    pValue: ptr::null_mut(),
                    ulValueLen: 0
                };
                count
            ],
            children: (0..count).map(|_| None).collect(),
            observed: None,
        })
    }
    fn pointer(&mut self) -> CK_VOID_PTR {
        if self.native.is_empty() {
            ptr::null_mut()
        } else {
            self.native.as_mut_ptr().cast()
        }
    }
    fn prepare(&mut self) -> Result<()> {
        for (attribute, child) in self.native.iter_mut().zip(&mut self.children) {
            if let Some(child) = child {
                child.prepare()?;
                attribute.pValue = child.pointer();
                attribute.ulValueLen =
                    (child.native.len() * size_of::<CK_ATTRIBUTE>()).try_into()?;
            } else {
                attribute.pValue = ptr::null_mut();
                attribute.ulValueLen = 0;
            }
        }
        Ok(())
    }
    fn inspect(&mut self, depth: usize, budget: &mut Budget) -> Result<bool> {
        let mut more = false;
        for (index, (attribute, child)) in self.native.iter().zip(&mut self.children).enumerate() {
            let expected_pointer = child.as_mut().map_or(ptr::null_mut(), Array::pointer);
            if attribute.pValue != expected_pointer {
                return Err(Error::InvalidValue);
            }
            if let Some(previous) = &self.observed {
                if previous[index] != (attribute.type_, attribute.ulValueLen) {
                    return Err(Error::InvalidValue);
                }
            }
            if let Some(child) = child {
                more |= child.inspect(depth + 1, budget)?;
            } else if attribute.ulValueLen != CK_UNAVAILABLE_INFORMATION
                && TemplateAttribute::from_native(attribute.type_).is_some()
            {
                let array = Array::new(attribute.ulValueLen.try_into()?, depth + 1, budget)?;
                more |= !array.native.is_empty();
                *child = Some(array);
            }
        }
        self.observed = Some(
            self.native
                .iter()
                .map(|a| (a.type_, a.ulValueLen))
                .collect(),
        );
        Ok(more)
    }
    #[allow(clippy::useless_conversion)]
    fn into_members(self) -> Result<Vec<TemplateMember>> {
        self.native
            .into_iter()
            .zip(self.children)
            .map(|(a, child)| {
                Ok(TemplateMember {
                    attribute_type: a.type_.into(),
                    status: if a.ulValueLen == CK_UNAVAILABLE_INFORMATION {
                        AttributeInfo::Unavailable
                    } else {
                        AttributeInfo::Available(a.ulValueLen.try_into()?)
                    },
                    template: child.map(Array::into_members).transpose()?,
                })
            })
            .collect()
    }
}

impl Session {
    /// Inspect wrap/unwrap/derive template structure with fixed depth, entry and
    /// allocation bounds. All leaf `pValue` pointers remain NULL; this method never
    /// retrieves secret or public leaf values and does not construct an operation
    /// template. Unknown array types are not interpreted as `CK_ATTRIBUTE` arrays.
    ///
    /// Each discovered level needs one call, plus the initial root length query.
    /// Changed types, lengths or pointers, excessive nesting, malformed array
    /// lengths and exceeded budgets return `InvalidValue`, without retries.
    pub fn get_template_metadata(
        &self,
        object: ObjectHandle,
        kind: TemplateAttribute,
    ) -> Result<TemplateMetadata> {
        let mut root = CK_ATTRIBUTE {
            type_: kind.native(),
            pValue: ptr::null_mut(),
            ulValueLen: 0,
        };
        let query = |root: &mut CK_ATTRIBUTE| -> Result<Rv> {
            // Only application-owned, initialized array storage is exposed. No
            // returned provider pointer is dereferenced, even for nested arrays.
            let rv = unsafe {
                Rv::from(get_pkcs11!(self.client(), C_GetAttributeValue)(
                    self.handle(),
                    object.handle(),
                    root,
                    1,
                ))
            };
            match rv {
                Rv::Ok | Rv::Error(RvError::AttributeSensitive | RvError::AttributeTypeInvalid) => {
                    Ok(rv)
                }
                _ => {
                    rv.into_result(Function::GetAttributeValue)?;
                    Ok(rv)
                }
            }
        };
        let rv = query(&mut root)?;
        if root.type_ != kind.native() || !root.pValue.is_null() {
            return Err(Error::InvalidValue);
        }
        if root.ulValueLen == CK_UNAVAILABLE_INFORMATION {
            return Ok(TemplateMetadata {
                kind,
                status: match rv {
                    Rv::Error(RvError::AttributeSensitive) => AttributeInfo::Sensitive,
                    Rv::Error(RvError::AttributeTypeInvalid) => AttributeInfo::TypeInvalid,
                    _ => AttributeInfo::Unavailable,
                },
                members: Vec::new(),
            });
        }
        let length = root.ulValueLen.try_into()?;
        let mut budget = Budget::default();
        let mut array = Array::new(length, 1, &mut budget)?;
        if !array.native.is_empty() {
            loop {
                array.prepare()?;
                let pointer = array.pointer();
                root.pValue = pointer;
                root.ulValueLen = length.try_into()?;
                let _ = query(&mut root)?;
                if root.type_ != kind.native()
                    || root.pValue != pointer
                    || root.ulValueLen != length.try_into()?
                {
                    return Err(Error::InvalidValue);
                }
                if !array.inspect(1, &mut budget)? {
                    break;
                }
            }
        }
        Ok(TemplateMetadata {
            kind,
            status: AttributeInfo::Available(length),
            members: array.into_members()?,
        })
    }
}
