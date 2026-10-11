// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Attribute, AttributeInfo, AttributeRead, Error, ObjectClass, Pkcs11Uri};

/// Build a secret-free object selector from available class, label and ID metadata.
/// Empty label/ID bytes remain exact constraints. Unrepresentable labels, missing
/// identity or an unsupported class return None. A locator is not proof of
/// uniqueness: inspect resolves it again.
pub fn object_locator(
    token: &Pkcs11Uri,
    attributes: &[AttributeRead],
) -> Result<Option<Pkcs11Uri>, Error> {
    build(
        token,
        attributes
            .iter()
            .filter_map(|read| {
                if !matches!(read.status, AttributeInfo::Available(_)) {
                    return None;
                }
                read.values.as_ref().map(|values| {
                    values
                        .expose_values()
                        .iter()
                        .filter(move |value| value.attribute_type() == read.kind)
                })
            })
            .flatten(),
    )
}

fn build<'a>(
    token: &Pkcs11Uri,
    attributes: impl Iterator<Item = &'a Attribute>,
) -> Result<Option<Pkcs11Uri>, Error> {
    crate::validate_token_uri(token)?;
    let mut class = None;
    let mut label = None;
    let mut id = None;
    for value in attributes {
        match value {
            Attribute::Class(value) => class = Some(*value),
            Attribute::Label(value) => label = Some(value.as_slice()),
            Attribute::Id(value) => id = Some(value.as_slice()),
            _ => {}
        }
    }
    let kind = match class {
        Some(ObjectClass::PRIVATE_KEY) => "private",
        Some(ObjectClass::PUBLIC_KEY) => "public",
        Some(ObjectClass::CERTIFICATE) => "cert",
        Some(ObjectClass::DATA) => "data",
        Some(ObjectClass::SECRET_KEY) => "secret-key",
        _ => return Ok(None),
    };
    if label.is_none() && id.is_none() {
        return Ok(None);
    }
    if label.is_some_and(|bytes| std::str::from_utf8(bytes).is_err()) {
        return Ok(None);
    }
    let build_uri = || -> Result<Pkcs11Uri, pkcs11_locator::Error> {
        let mut builder = Pkcs11Uri::builder();
        for (name, value) in token.path_attributes() {
            builder = builder.path_attribute(name, value)?;
        }
        for value in token.query_values("module-path") {
            builder = builder.query_attribute("module-path", value.clone())?;
        }
        builder = builder.path_attribute("type", kind.as_bytes())?;
        if let Some(value) = label {
            builder = builder.path_attribute("object", value)?;
        }
        if let Some(value) = id {
            builder = builder.path_attribute("id", value)?;
        }
        builder.build()
    };
    let uri = build_uri().map_err(pkcs11_runtime::Error::from)?;
    Ok(Some(uri))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn identity_bytes_empty_constraints_and_location_survive() {
        let path = std::env::current_dir().unwrap().join("trusted.so");
        let path = path.to_str().unwrap();
        let token = Pkcs11Uri::builder()
            .path_attribute("token", b"test")
            .unwrap()
            .path_attribute("serial", b"123")
            .unwrap()
            .query_attribute("module-path", path.into())
            .unwrap()
            .build()
            .unwrap();
        let attributes = [
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(Vec::new()),
            Attribute::Id(vec![0, 255]),
        ];
        let uri = build(&token, attributes.iter()).unwrap().unwrap();
        assert_eq!(uri.path_attribute("object"), Some(b"".as_slice()));
        assert_eq!(uri.path_attribute("id"), Some([0, 255].as_slice()));
        assert_eq!(uri.path_attribute("serial"), Some(b"123".as_slice()));
        assert_eq!(
            uri.query_values("module-path")
                .next()
                .unwrap()
                .expose_secret(),
            path
        );
        crate::object_reference(uri).unwrap();
    }

    #[test]
    fn incomplete_metadata_does_not_create_a_broad_selector() {
        let token = "pkcs11:token=test".parse().unwrap();
        for attributes in [
            vec![Attribute::Class(ObjectClass::PUBLIC_KEY)],
            vec![Attribute::Label(b"key".to_vec())],
        ] {
            assert!(build(&token, attributes.iter()).unwrap().is_none());
        }
        assert!(object_locator(&token, &[]).unwrap().is_none());
        let binary = [
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(vec![255]),
            Attribute::Id(vec![1]),
        ];
        assert!(build(&token, binary.iter()).unwrap().is_none());
    }

    #[test]
    fn credentials_and_object_values_cannot_enter_a_locator() {
        let token = "pkcs11:token=test".parse().unwrap();
        let attributes = [
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(b"public".to_vec()),
            Attribute::Value(b"secret-canary".to_vec()),
        ];
        assert!(
            !build(&token, attributes.iter())
                .unwrap()
                .unwrap()
                .to_string()
                .contains("secret-canary")
        );
        let bad = "pkcs11:token=test?pin-value=secret-canary".parse().unwrap();
        let error = build(&bad, attributes.iter()).unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::Input);
        assert!(!format!("{error:?}").contains("secret-canary"));
    }
}
