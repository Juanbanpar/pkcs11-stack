// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Authentication, Client, Error, ObjectRef, Pkcs11Uri, SecretText};

impl Client<'_> {
    /// Resolve exactly one secret key and return its selector with `type=secret-key`.
    /// A URI with an explicit class must already specify `type=secret-key`.
    pub fn secret_key(
        &self,
        uri: Pkcs11Uri,
        authentication: Authentication<'_>,
    ) -> Result<ObjectRef, Error> {
        let key = secret_key_reference(uri)?;
        self.pool()
            .try_acquire(authentication)?
            .session()
            .resolve(&key)?;
        Ok(key)
    }
}

fn secret_key_reference(uri: Pkcs11Uri) -> Result<ObjectRef, pkcs11_runtime::Error> {
    let reference = ObjectRef::new(uri)?;
    let uri = reference.uri();
    match uri.path_attribute("type") {
        Some(b"secret-key") => return Ok(reference),
        Some(_) => return Err(pkcs11_runtime::Error::InvalidObjectReference),
        None => {}
    }

    let mut builder = Pkcs11Uri::builder().path_attribute("type", b"secret-key")?;
    for (name, value) in uri.path_attributes() {
        builder = builder.path_attribute(name, value)?;
    }
    if let Some(path) = uri.query_values("module-path").next() {
        builder = builder.query_attribute("module-path", SecretText::from(path.expose_secret()))?;
    }
    ObjectRef::new(builder.build()?)
}
