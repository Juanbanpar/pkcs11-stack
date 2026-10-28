// SPDX-License-Identifier: MIT OR Apache-2.0
//! Token hashes compared with independent OpenSSL output.
use pkcs11_runtime::{
    Authentication, CancelFlags, DigestMode, Error, HashAlgorithm, Module, SessionMode, SessionPool,
};
use std::{
    io::Write,
    num::NonZeroUsize,
    process::{Command, Stdio},
};

fn openssl(algorithm: HashAlgorithm, message: &[u8]) -> Vec<u8> {
    let mut child = Command::new("openssl")
        .args(["dgst", &format!("-{algorithm}"), "-binary"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(message).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "OpenSSL hash failed: {}",
        output.status
    );
    output.stdout
}
#[test]
#[ignore = "requires the disposable SoftHSM or Kryoptic runner"]
fn fixed_hashes_singlepart_multipart_and_discarded_pool_sessions() {
    let kdf = std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref() == Ok("1");
    assert!(kdf || std::env::var("PKCS11_TEST_ISOLATED").as_deref() == Ok("1"));
    let module = Module::load(
        std::env::var_os(if kdf {
            "PKCS11_TEST_KDF_MODULE"
        } else {
            "PKCS11_TEST_MODULE"
        })
        .unwrap(),
    )
    .unwrap();
    let token = module
        .resolve_token_uri(
            &format!(
                "pkcs11:token={}",
                if kdf { "kdf-test" } else { "client-test" }
            )
            .parse()
            .unwrap(),
        )
        .unwrap();
    let single = token.digest_algorithms(DigestMode::SinglePart).unwrap();
    let multipart = token.digest_algorithms(DigestMode::Multipart).unwrap();
    if kdf {
        assert_eq!(multipart, HashAlgorithm::ALL);
    }
    for algorithm in [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ] {
        assert!(single.contains(&algorithm) && multipart.contains(&algorithm));
    }
    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
    for algorithm in single.into_iter().filter(|a| multipart.contains(a)) {
        for message in [
            vec![],
            b"abc".to_vec(),
            (0..1024 * 1024 + 17).map(|i| (i % 251) as u8).collect(),
        ] {
            let expected = openssl(algorithm, &message);
            assert_eq!(
                session.digest(algorithm, &message).unwrap(),
                expected,
                "{algorithm}"
            );
            let mut operation = session.start_digest(algorithm).unwrap();
            operation.update(b"").unwrap();
            for chunk in message.chunks(8191) {
                operation.update(chunk).unwrap();
            }
            assert_eq!(operation.finish().unwrap(), expected, "{algorithm}");
            session.info().unwrap();
        }
    }
    let mut operation = session.start_digest(HashAlgorithm::Sha256).unwrap();
    operation.update(b"cancel this digest").unwrap();
    let cancelled = operation.cancel();
    if kdf {
        cancelled.unwrap();
        session.info().unwrap();
        assert_eq!(
            session.digest(HashAlgorithm::Sha256, b"abc").unwrap(),
            openssl(HashAlgorithm::Sha256, b"abc")
        );
        session.cancel_operations(CancelFlags::empty()).unwrap();
    } else if cancelled.is_err() {
        assert!(matches!(session.info(), Err(Error::Closed)));
        session.close().unwrap();
        session = token.open_session(SessionMode::ReadOnly).unwrap();
    }
    drop(session.start_digest(HashAlgorithm::Sha256).unwrap());
    assert!(matches!(session.info(), Err(Error::Closed)));
    session.close().unwrap();
    let pool = SessionPool::new(token, SessionMode::ReadOnly, NonZeroUsize::new(1).unwrap());
    {
        let mut lease = pool.try_acquire(Authentication::None).unwrap();
        let mut operation = lease.session().start_digest(HashAlgorithm::Sha256).unwrap();
        operation.update(b"unfinished canary").unwrap();
        drop(operation);
    }
    {
        let mut lease = pool.try_acquire(Authentication::None).unwrap();
        assert_eq!(
            lease
                .session()
                .digest(HashAlgorithm::Sha256, b"abc")
                .unwrap(),
            openssl(HashAlgorithm::Sha256, b"abc")
        );
    }
    pool.close().unwrap();
    module.finalize().unwrap();
}
