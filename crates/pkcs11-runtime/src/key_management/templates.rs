// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Attribute, Error, KeyType, ObjectClass, Session};

pub(crate) fn validate_secret_identity(id: &[u8], label: &[u8]) -> Result<(), Error> {
    if id.is_empty() || id.len() > 128 || label.is_empty() || label.len() > 128 {
        return Err(Error::InvalidParameters("secret key identity"));
    }
    Ok(())
}
fn identity_template(id: &[u8], label: &[u8], aes: bool) -> Result<Vec<Attribute>, Error> {
    validate_secret_identity(id, label)?;
    Ok(vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(if aes {
            KeyType::AES
        } else {
            KeyType::GENERIC_SECRET
        }),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Id(id.to_vec()),
        Attribute::Label(label.to_vec()),
        Attribute::Encrypt(aes),
        Attribute::Decrypt(aes),
        Attribute::Sign(false),
        Attribute::Verify(false),
        Attribute::Wrap(false),
        Attribute::Unwrap(false),
        Attribute::Derive(!aes),
    ])
}

impl Session<'_> {
    pub(crate) fn new_secret_template(
        &mut self,
        id: &[u8],
        label: &[u8],
        aes: bool,
    ) -> Result<Vec<Attribute>, Error> {
        let template = identity_template(id, label, aes)?;
        if !self
            .find_objects(&[
                Attribute::Token(true),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::Id(id.to_vec()),
            ])?
            .is_empty()
        {
            return Err(Error::InvalidParameters("secret key ID already exists"));
        }
        Ok(template)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_template_never_grants_extractability_or_transfer_permissions() {
        let attrs = identity_template(b"id", b"key", true).unwrap();
        for attr in [
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Private(true),
            Attribute::Token(true),
            Attribute::Wrap(false),
            Attribute::Unwrap(false),
            Attribute::Derive(false),
        ] {
            assert!(attrs.contains(&attr));
        }
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Value(_))));
        let material = identity_template(b"id", b"material", false).unwrap();
        for attr in [
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Derive(true),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Wrap(false),
            Attribute::Unwrap(false),
        ] {
            assert!(material.contains(&attr));
        }
        assert!(identity_template(b"", b"key", true).is_err());
        assert!(identity_template(b"id", &[0; 129], true).is_err());
    }
}
