// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Error, Session, SessionMode,
    error::{backend, function_not_supported},
};

impl Session<'_> {
    // Enter the native operation with the session already marked unusable. The
    // caller restores it only after a terminal result that permits reuse.
    pub(crate) fn begin_operation(&self) -> Result<&cryptoki::session::Session, Error> {
        let raw = self.raw()?;
        self.healthy.set(false);
        Ok(raw)
    }

    /// Run one read-only native operation with session health tracking.
    ///
    /// The session is marked unhealthy before the native call so a panic or
    /// error can never return an active operation to a pool.
    pub(crate) fn operation<T>(
        &self,
        operation: &'static str,
        action: impl FnOnce(&cryptoki::session::Session) -> Result<T, cryptoki::error::Error>,
    ) -> Result<T, Error> {
        self.validate()?;
        let raw = self.begin_operation()?;
        match action(raw) {
            Ok(value) => {
                self.healthy.set(true);
                Ok(value)
            }
            Err(source) => {
                // A stub that reports CKR_FUNCTION_NOT_SUPPORTED did not start
                // an operation, so the session remains usable.
                if function_not_supported(&source) {
                    self.healthy.set(true);
                }
                Err(backend(operation, source))
            }
        }
    }
    pub(crate) fn write_operation<T>(
        &self,
        operation: &'static str,
        action: impl FnOnce(&cryptoki::session::Session) -> Result<T, cryptoki::error::Error>,
    ) -> Result<T, Error> {
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        self.operation(operation, action)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroUsize,
        panic::{AssertUnwindSafe, catch_unwind},
    };

    use crate::{Authentication, Error, Module, SessionMode, SessionPool};

    #[test]
    #[ignore = "requires the disposable SoftHSM store in tools/test-softhsm.sh"]
    fn caught_operation_panic_discards_the_lease() {
        assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
        let module = Module::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
        let token = module.tokens().unwrap().into_iter().next().unwrap();
        let pool = SessionPool::new(token, SessionMode::ReadOnly, NonZeroUsize::MIN);
        let mut lease = pool.try_acquire(Authentication::None).unwrap();
        let generation = lease.generation();

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = lease
                .session()
                .operation::<()>("test operation", |_| panic!("fixture unwind"));
        }));
        assert!(result.is_err());
        assert!(matches!(lease.session().info(), Err(Error::Closed)));
        drop(lease);

        let mut next = pool.try_acquire(Authentication::None).unwrap();
        assert_ne!(next.generation(), generation);
        next.session().info().unwrap();
        drop(next);
        pool.close().unwrap();
        module.finalize().unwrap();
    }
}
