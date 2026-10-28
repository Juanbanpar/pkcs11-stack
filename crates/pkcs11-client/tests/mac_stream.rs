// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded readers, interrupted/failed input, guard ownership and client errors.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/mac_stream_module.rs"]
mod fixture;
use fixture::MacStreamModule;
use pkcs11_client::*;
use std::io::{self, Read};

struct Input {
    remaining: usize,
    maximum_buffer: usize,
    interrupted: bool,
    fail: bool,
}
impl Read for Input {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.maximum_buffer = self.maximum_buffer.max(out.len());
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.remaining == 0 {
            return if self.fail {
                Err(io::Error::other("reader diagnostics canary"))
            } else {
                Ok(0)
            };
        }
        let length = self.remaining.min(out.len()).min(3071);
        out[..length].fill(0xA5);
        self.remaining -= length;
        Ok(length)
    }
}
#[test]
fn readers_use_bounded_chunks_support_large_input_and_map_completed_mismatches() {
    for (hmac, general) in [(false, false), (false, true), (true, false), (true, true)] {
        let fixture = MacStreamModule::new(3, 2, 0, hmac, general);
        let provider = Provider::load(fixture.path()).unwrap();
        let mut session = provider
            .management(
                &"pkcs11:token=cmac".parse().unwrap(),
                SessionMode::ReadOnly,
                Authentication::None,
            )
            .unwrap();
        let key =
            ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap();
        let hp = if general {
            HmacTagProfile::General { tag_length: 16 }
        } else {
            HmacTagProfile::Full
        };
        let cp = if general {
            AesCmacProfile::General { tag_length: 8 }
        } else {
            AesCmacProfile::Full
        };
        for length in [0, 17 * 1024 * 1024 + 1] {
            let mut input = Input {
                remaining: length,
                maximum_buffer: 0,
                interrupted: false,
                fail: false,
            };
            let tag = if hmac {
                session
                    .hmac_reader(&key, HmacAlgorithm::Sha256, hp, &mut input)
                    .unwrap()
            } else {
                session.aes_cmac_reader(&key, cp, &mut input).unwrap()
            };
            assert_eq!(input.remaining, 0);
            assert_eq!(input.maximum_buffer, 64 * 1024);
            session.state().unwrap();
            for supplied in [tag.clone(), vec![], vec![0xAC; tag.len()]] {
                input.remaining = length;
                let result = if hmac {
                    session.verify_hmac_reader(
                        &key,
                        HmacAlgorithm::Sha256,
                        hp,
                        &mut input,
                        &supplied,
                    )
                } else {
                    session.verify_aes_cmac_reader(&key, cp, &mut input, &supplied)
                };
                if supplied == tag {
                    result.unwrap();
                } else {
                    assert!(matches!(result, Err(Error::MacMismatch)));
                }
                assert_eq!(input.remaining, 0);
                session.state().unwrap();
            }
        }
        // Client consuming guards expose explicit cancellation for both directions.
        if hmac {
            session
                .start_hmac(&key, HmacAlgorithm::Sha256, hp)
                .unwrap()
                .cancel()
                .unwrap();
            session
                .start_hmac_verification(&key, HmacAlgorithm::Sha256, hp)
                .unwrap()
                .cancel()
                .unwrap();
        } else {
            session.start_aes_cmac(&key, cp).unwrap().cancel().unwrap();
            session
                .start_aes_cmac_verification(&key, cp)
                .unwrap()
                .cancel()
                .unwrap();
        }
        session.state().unwrap();
        session.close().unwrap();
        provider.finalize().unwrap();
    }
}
#[test]
fn partial_read_failure_discards_both_directions_without_leaking_diagnostics() {
    for hmac in [false, true] {
        for generation in [false, true] {
            let fixture = MacStreamModule::new(3, 2, 0, hmac, false);
            let provider = Provider::load(fixture.path()).unwrap();
            let token = "pkcs11:token=cmac".parse().unwrap();
            let watcher = provider
                .management(&token, SessionMode::ReadOnly, Authentication::None)
                .unwrap();
            let mut session = provider
                .management(&token, SessionMode::ReadOnly, Authentication::None)
                .unwrap();
            let key = ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap())
                .unwrap();
            let mut input = Input {
                remaining: 12,
                maximum_buffer: 0,
                interrupted: false,
                fail: true,
            };
            let error = match (hmac, generation) {
                (true, true) => session
                    .hmac_reader(
                        &key,
                        HmacAlgorithm::Sha256,
                        HmacTagProfile::Full,
                        &mut input,
                    )
                    .unwrap_err(),
                (true, false) => session
                    .verify_hmac_reader(
                        &key,
                        HmacAlgorithm::Sha256,
                        HmacTagProfile::Full,
                        &mut input,
                        &[0xAB; 32],
                    )
                    .unwrap_err(),
                (false, true) => session
                    .aes_cmac_reader(&key, AesCmacProfile::Full, &mut input)
                    .unwrap_err(),
                (false, false) => session
                    .verify_aes_cmac_reader(&key, AesCmacProfile::Full, &mut input, &[0xAB; 16])
                    .unwrap_err(),
            };
            assert!(matches!(error, Error::MacInput));
            assert_eq!(error.kind(), ErrorKind::Input);
            assert!(!format!("{error:?} {error}").contains("canary"));
            assert!(session.state().is_err());
            watcher.state().unwrap();
            session.close().unwrap();
            watcher.close().unwrap();
            provider.finalize().unwrap();
        }
    }
}
