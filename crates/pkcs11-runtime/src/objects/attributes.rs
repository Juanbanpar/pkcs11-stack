// SPDX-License-Identifier: MIT OR Apache-2.0
use std::fmt;

use crate::{Attribute, AttributeInfo, AttributeType, Error, Object};

/// Attribute data with redacted Debug; values require explicit access.
pub struct AttributeValues(Vec<Attribute>);
impl AttributeValues {
    pub(super) fn new(values: Vec<Attribute>) -> Self {
        Self(values)
    }

    /// Explicit access to cryptoki values. Their own Debug may reveal secret material.
    pub fn expose_values(&self) -> &[Attribute] {
        &self.0
    }
}
impl fmt::Debug for AttributeValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttributeValues")
            .field(
                "types",
                &self
                    .0
                    .iter()
                    .map(Attribute::attribute_type)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

pub(crate) fn attribute(
    object: &Object<'_, '_>,
    ty: AttributeType,
    required: bool,
) -> Result<Option<Attribute>, Error> {
    let info = object.attribute_info(&[ty])?;
    match info.first() {
        Some(AttributeInfo::Available(_)) => {
            let values = object.read_attributes(&[ty])?;
            let value = values.expose_values().first().cloned();
            if value.is_none() {
                return Err(Error::MissingMetadata("attribute changed during read"));
            }
            Ok(value)
        }
        Some(AttributeInfo::TypeInvalid) if !required => Ok(None),
        _ => Err(Error::MissingMetadata("required or restricted attribute")),
    }
}

pub(crate) fn key_permission(
    object: &crate::Object<'_, '_>,
    kind: AttributeType,
) -> Result<bool, Error> {
    Ok(matches!(
        attribute(object, kind, true)?,
        Some(
            Attribute::Derive(true)
                | Attribute::Wrap(true)
                | Attribute::Unwrap(true)
                | Attribute::Extractable(true)
                | Attribute::Trusted(true)
        )
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_debug_does_not_expose_values() {
        let attrs = AttributeValues(vec![Attribute::Value(b"canary".to_vec())]);
        assert!(!format!("{attrs:?}").contains(&format!("{:?}", b"canary".to_vec())));
        assert_eq!(
            attrs.expose_values(),
            &[Attribute::Value(b"canary".to_vec())]
        );
    }
}
