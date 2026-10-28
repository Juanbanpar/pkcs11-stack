// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reader bounds, interrupted input and discard behavior on disposable providers.
use pkcs11_client::{
    Authentication, CancelFlags, DigestMode, Error, HashAlgorithm, Provider, SessionMode,
};
use sha2::{Digest, Sha256};
use std::io::{self, Read};

struct InterruptedThenInput {
    interrupted: bool,
    bytes: io::Cursor<Vec<u8>>,
    maximum_buffer: usize,
}
impl Read for InterruptedThenInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.maximum_buffer = self.maximum_buffer.max(output.len());
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let length = output.len().min(3071);
        self.bytes.read(&mut output[..length])
    }
}
struct FailedInput;
impl Read for FailedInput {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other(
            "reader error canary that must not appear in diagnostics",
        ))
    }
}
#[test]
#[ignore = "requires the disposable SoftHSM or Kryoptic runner"]
fn reader_chunks_interrupted_reads_and_failed_input_discard() {
    let kdf = std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref() == Ok("1");
    assert!(kdf || std::env::var("PKCS11_TEST_ISOLATED").as_deref() == Ok("1"));
    let provider = Provider::load(
        std::env::var_os(if kdf {
            "PKCS11_TEST_KDF_MODULE"
        } else {
            "PKCS11_TEST_MODULE"
        })
        .unwrap(),
    )
    .unwrap();
    let uri = format!(
        "pkcs11:token={}",
        if kdf { "kdf-test" } else { "client-test" }
    )
    .parse()
    .unwrap();
    let mut session = provider
        .management(&uri, SessionMode::ReadOnly, Authentication::None)
        .unwrap();
    assert!(
        session
            .digest_algorithms(DigestMode::Multipart)
            .unwrap()
            .contains(&HashAlgorithm::Sha256)
    );
    let data: Vec<u8> = (0..1_000_003).map(|i| (i % 251) as u8).collect();
    let expected = Sha256::digest(&data).to_vec();
    let mut reader = InterruptedThenInput {
        interrupted: false,
        bytes: io::Cursor::new(data),
        maximum_buffer: 0,
    };
    assert_eq!(
        session
            .digest_reader(HashAlgorithm::Sha256, &mut reader)
            .unwrap(),
        expected
    );
    assert_eq!(reader.maximum_buffer, 64 * 1024);
    session.state().unwrap();
    let mut operation = session.start_digest(HashAlgorithm::Sha256).unwrap();
    operation.update(b"cancel this digest").unwrap();
    let cancelled = operation.cancel();
    if kdf {
        cancelled.unwrap();
        session.state().unwrap();
        session.cancel_operations(CancelFlags::empty()).unwrap();
        let mut next = session.start_digest(HashAlgorithm::Sha256).unwrap();
        next.update(b"abc").unwrap();
        assert_eq!(next.finish().unwrap(), Sha256::digest(b"abc").to_vec());
    } else if cancelled.is_err() {
        assert!(session.state().is_err());
        session.close().unwrap();
        session = provider
            .management(&uri, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
    }
    let error = session
        .digest_reader(HashAlgorithm::Sha256, &mut FailedInput)
        .unwrap_err();
    assert!(matches!(error, Error::DigestInput));
    assert!(!format!("{error:?}").contains("canary"));
    assert!(session.state().is_err());
    assert!(session.digest_algorithms(DigestMode::Multipart).is_err());
    session.close().unwrap();
    provider.finalize().unwrap();
}
