// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Authentication, Error, Session, SessionMode, SessionState, Token};
use cryptoki::error::RvError;
use std::{num::NonZeroUsize, sync::Mutex};

struct Entry<'m> {
    session: Session<'m>,
    generation: u64,
}
struct State<'m> {
    idle: Vec<Entry<'m>>,
    total: usize,
    generation: u64,
    cleanup_error: Option<Error>,
}
impl State<'_> {
    fn record_cleanup(&mut self, result: Result<(), Error>) {
        if let Err(error) = result {
            self.cleanup_error.get_or_insert(error);
        }
    }
    fn close(mut self) -> Result<(), Error> {
        for entry in self.idle {
            if let Err(error) = entry.session.close() {
                self.cleanup_error.get_or_insert(error);
            }
        }
        self.cleanup_error.map_or(Ok(()), Err)
    }
    fn check_cleanup(&self) -> Result<(), Error> {
        if self.cleanup_error.is_some() {
            Err(Error::PoolCleanupFailed)
        } else {
            Ok(())
        }
    }
}
/// Bounded, token-scoped pool. Checkout is nonblocking and never stores a PIN.
///
/// Only accounting is locked. Every lease owns a separate session. Use one pool
/// per token/authentication role; token-wide logout by outside callers is not isolated.
pub struct SessionPool<'m> {
    token: Token<'m>,
    mode: SessionMode,
    maximum: NonZeroUsize,
    state: Mutex<State<'m>>,
}
impl SessionPool<'static> {
    /// Create an owned pool suitable for long-lived consumers such as TLS signers.
    ///
    /// Shares one existing initialization owner; no module is loaded or reinitialized.
    /// Idle/leased sessions keep that owner alive until after their handles close.
    /// Drop all pools/consumers, then `Arc::try_unwrap(module)` for explicit finalize.
    pub fn new_owned(
        module: std::sync::Arc<crate::Module>,
        uri: &pkcs11_locator::Pkcs11Uri,
        mode: SessionMode,
        maximum: NonZeroUsize,
    ) -> Result<Self, Error> {
        let token = module.resolve_token_uri(uri)?;
        let slot = token.slot;
        let info = token.info.clone();
        let token = Token {
            module: crate::module::ModuleRef::Shared(module),
            slot,
            info,
        };
        Ok(Self::new(token, mode, maximum))
    }
}
impl<'m> SessionPool<'m> {
    /// Create a lazy pool; no session is opened until checkout.
    pub fn new(token: Token<'m>, mode: SessionMode, maximum: NonZeroUsize) -> Self {
        Self {
            token,
            mode,
            maximum,
            state: Mutex::new(State {
                idle: vec![],
                total: 0,
                generation: 0,
                cleanup_error: None,
            }),
        }
    }
    /// Lease a healthy session, replacing a stale idle session once if necessary.
    ///
    /// Authentication means ensure the requested role, accepting a concurrent
    /// successful login only after verifying actual session state. None leaves
    /// token-wide state unchanged. No operation or failed PIN is retried.
    pub fn try_acquire(
        &self,
        authentication: Authentication<'_>,
    ) -> Result<SessionLease<'_, 'm>, Error> {
        let (entry, generation) = {
            let mut state = self.state.lock().map_err(|_| Error::PoolPoisoned)?;
            state.check_cleanup()?;
            let generation = state
                .generation
                .checked_add(1)
                .ok_or(Error::PoolExhausted)?;
            let entry = state.idle.pop();
            if entry.is_none() && state.total == self.maximum.get() {
                return Err(Error::PoolExhausted);
            }

            state.generation = generation;
            if entry.is_none() {
                state.total += 1;
            }
            (entry, generation)
        };
        // Reservation is owned by the lease immediately, including failed opens/panics.
        let mut lease = SessionLease {
            pool: self,
            entry,
            reusable: false,
        };
        if lease
            .entry
            .as_ref()
            .is_some_and(|e| !e.session.healthy.get() || e.session.info().is_err())
        {
            let closed = lease.close_entry();
            let mut state = self.state.lock().map_err(|_| Error::PoolPoisoned)?;
            state.record_cleanup(closed);
            state.check_cleanup()?;
        }
        if lease.entry.is_none() {
            lease.entry = Some(Entry {
                session: self.token.open_session(self.mode)?,
                generation,
            });
        }
        let session = lease.session();
        let desired = match &authentication {
            Authentication::None => None,
            Authentication::User(_) => Some(false),
            Authentication::SecurityOfficer(_) => Some(true),
        };
        if let Some(so) = desired {
            if !role_matches(session.info()?.session_state(), so) {
                match session.authenticate(authentication) {
                    Ok(()) => {}
                    Err(Error::Backend {
                        source: cryptoki::error::Error::Pkcs11(RvError::UserAlreadyLoggedIn, _),
                        ..
                    }) if role_matches(session.info()?.session_state(), so) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        lease.reusable = true;
        Ok(lease)
    }
    /// Close every idle session and report the first cleanup failure, including
    /// one recorded when a stale or failed lease was discarded. All sessions are
    /// attempted even after an error. No logout or operation retry is performed.
    ///
    /// Outstanding leases borrow this pool and must be released before closure.
    /// Drop remains best effort when explicit closure is not used.
    ///
    /// ```compile_fail,E0505
    /// use pkcs11_runtime::{Authentication, SessionPool};
    /// fn invalid_close(pool: SessionPool<'_>) {
    ///     let lease = pool.try_acquire(Authentication::None).unwrap();
    ///     pool.close().unwrap();
    ///     drop(lease);
    /// }
    /// ```
    pub fn close(self) -> Result<(), Error> {
        let (state, poisoned) = match self.state.into_inner() {
            Ok(state) => (state, false),
            Err(error) => (error.into_inner(), true),
        };
        let closed = state.close();
        if poisoned {
            closed.and(Err(Error::PoolPoisoned))
        } else {
            closed
        }
    }
    /// Configured maximum, counting idle, leased and opening sessions.
    pub fn maximum(&self) -> NonZeroUsize {
        self.maximum
    }
}
fn role_matches(state: SessionState, so: bool) -> bool {
    if so {
        state == SessionState::RwSecurityOfficer
    } else {
        matches!(state, SessionState::RoUser | SessionState::RwUser)
    }
}
/// Exclusive session ownership returned to its pool by Drop.
/// A panic or failed signing operation makes the session ineligible for reuse.
pub struct SessionLease<'p, 'm> {
    pool: &'p SessionPool<'m>,
    entry: Option<Entry<'m>>,
    reusable: bool,
}
impl<'m> SessionLease<'_, 'm> {
    fn close_entry(&mut self) -> Result<(), Error> {
        self.entry
            .take()
            .map_or(Ok(()), |entry| entry.session.close())
    }
    /// Borrow the leased session exclusively. Objects cannot outlive this borrow.
    pub fn session(&mut self) -> &mut Session<'m> {
        &mut self.entry.as_mut().expect("live lease").session
    }
    /// Diagnostic session generation, never a PKCS#11 handle or persistent identity.
    pub fn generation(&self) -> u64 {
        self.entry.as_ref().expect("live lease").generation
    }
    /// Force closure at lease drop, even if the module still reports it healthy.
    pub fn discard(&mut self) {
        self.reusable = false;
    }
}
impl Drop for SessionLease<'_, '_> {
    fn drop(&mut self) {
        let healthy = self.reusable
            && !std::thread::panicking()
            && self.entry.as_ref().is_some_and(|e| {
                e.session.healthy.get()
                    && e.session.info().is_ok()
                    && std::ptr::eq(&*e.session.token().module, &*self.pool.token.module)
                    && e.session.token().slot() == self.pool.token.slot()
                    && crate::module::same_token(e.session.token().info(), self.pool.token.info())
                    && e.session.mode == self.pool.mode
            });
        if healthy {
            if let Ok(mut state) = self.pool.state.lock() {
                if let Some(entry) = self.entry.take() {
                    state.idle.push(entry);
                    return;
                }
            }
        }
        // Keep it counted until close completes; no module call under the mutex.
        let closed = self.close_entry();
        let mut state = self
            .pool
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.total -= 1;
        state.record_cleanup(closed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discarded_session_close_failure_blocks_checkout_and_is_not_cleared() {
        let mut state = State {
            idle: Vec::new(),
            total: 0,
            generation: 0,
            cleanup_error: None,
        };
        assert!(state.check_cleanup().is_ok());
        state.record_cleanup(Ok(()));
        assert!(state.check_cleanup().is_ok());
        state.record_cleanup(Err(Error::Closed));
        state.record_cleanup(Ok(()));
        state.record_cleanup(Err(Error::PoolPoisoned));
        assert!(matches!(
            state.check_cleanup(),
            Err(Error::PoolCleanupFailed)
        ));
        assert!(matches!(state.close(), Err(Error::Closed)));
    }
}
