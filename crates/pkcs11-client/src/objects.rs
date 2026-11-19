// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Authentication, Client, Error, ObjectRef, Pkcs11Uri};

impl Client<'_> {
    /// Resolve exactly one secret key; retain its selector, never its handle.
    pub fn secret_key(
        &self,
        uri: Pkcs11Uri,
        authentication: Authentication<'_>,
    ) -> Result<ObjectRef, Error> {
        let key = ObjectRef::new(uri)?;
        self.pool()
            .try_acquire(authentication)?
            .session()
            .resolve(&key)?;
        Ok(key)
    }
}
