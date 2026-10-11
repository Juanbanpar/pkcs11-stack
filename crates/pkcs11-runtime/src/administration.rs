// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Attribute, Error, KeyKind, NamedCurve, Object, Session, SessionMode, error::backend};
use cryptoki::mechanism::Mechanism;
use secrecy::SecretString;

impl<'m> Session<'m> {
    pub(crate) fn write_operation<T>(
        &self,
        operation: &'static str,
        action: impl FnOnce(&cryptoki::session::Session) -> Result<T, cryptoki::error::Error>,
    ) -> Result<T, Error> {
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        let raw = self.raw()?;
        self.healthy.set(false);
        let result = action(raw).map_err(|e| backend(operation, e))?;
        self.healthy.set(true);
        Ok(result)
    }
    /// Initialize/reset the USER PIN. Requires an RW session logged in as SO.
    /// Uses a host PIN; the upstream API does not support a null/protected-path PIN.
    pub fn initialize_pin(&mut self, pin: &SecretString) -> Result<(), Error> {
        self.write_operation("initialize user PIN", |raw| raw.init_pin(pin))
    }
    /// Change the current role's PIN once. No credentials are retained or retried.
    /// Host PINs are required by the upstream safe mutation API.
    pub fn change_pin(&mut self, old: &SecretString, new: &SecretString) -> Result<(), Error> {
        self.write_operation("change PIN", |raw| raw.set_pin(old, new))
    }
    /// Create an object from an explicit template. Template data may contain secrets.
    /// Persistence, privacy and sensitivity are chosen by the caller's template.
    pub fn create_object(&mut self, template: &[Attribute]) -> Result<Object<'_, 'm>, Error> {
        let handle = self.write_operation("create object", |raw| raw.create_object(template))?;
        Ok(Object {
            session: self,
            handle,
        })
    }
    /// Generate a persistent RSA or named EC signing pair with a shared label/ID.
    /// Private keys are sensitive and nonextractable. No mechanism fallback occurs.
    /// RSA is bounded to 2048..=16384 bits; provider bounds may be narrower.
    pub fn generate_signing_key_pair(
        &mut self,
        kind: KeyKind,
        id: &[u8],
        label: &[u8],
        always_authenticate: bool,
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        if id.is_empty() {
            return Err(Error::InvalidParameters("key ID must not be empty"));
        }
        let mut public = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Label(label.to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::Verify(true),
        ];
        let private = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Label(label.to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::AlwaysAuthenticate(always_authenticate),
        ];
        let mechanism = match kind {
            KeyKind::Rsa { bits } => {
                if !(2048..=16384).contains(&bits) || bits % 8 != 0 {
                    return Err(Error::InvalidParameters("invalid RSA key size"));
                }
                public.extend([
                    Attribute::ModulusBits(
                        bits.try_into()
                            .map_err(|_| Error::InvalidParameters("invalid RSA key size"))?,
                    ),
                    Attribute::PublicExponent(vec![1, 0, 1]),
                ]);
                Mechanism::RsaPkcsKeyPairGen
            }
            KeyKind::Ec(curve) => {
                public.push(Attribute::EcParams(match curve {
                    NamedCurve::P256 => vec![6, 8, 42, 134, 72, 206, 61, 3, 1, 7],
                    NamedCurve::P384 => vec![6, 5, 43, 129, 4, 0, 34],
                    NamedCurve::P521 => vec![6, 5, 43, 129, 4, 0, 35],
                }));
                Mechanism::EccKeyPairGen
            }
        };
        let (public, private) = self.write_operation("generate signing key pair", |raw| {
            raw.generate_key_pair(&mechanism, &public, &private)
        })?;
        Ok((
            Object {
                session: self,
                handle: public,
            },
            Object {
                session: self,
                handle: private,
            },
        ))
    }
}
impl Object<'_, '_> {
    /// Update explicit attributes once. Provider failures may have partial effects.
    /// The session is invalidated on failure; no rollback or retry is attempted.
    pub fn update_attributes(&mut self, template: &[Attribute]) -> Result<(), Error> {
        self.session.write_operation("update attributes", |raw| {
            raw.update_attributes(self.handle, template)
        })
    }
    /// Destroy this selected object once. Consumes the session-bound wrapper.
    pub fn destroy(self) -> Result<(), Error> {
        self.session
            .write_operation("destroy object", |raw| raw.destroy_object(self.handle))
    }
}
