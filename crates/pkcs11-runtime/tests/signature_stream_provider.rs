// SPDX-License-Identifier: MIT OR Apache-2.0
//! Required real-provider signature cancellation and confirmed pool reuse.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    session::UserType,
};
use pkcs11_runtime::*;
use secrecy::SecretString;
use std::num::NonZeroUsize;

#[test]
#[ignore = "requires the disposable Kryoptic runner"]
fn signature_cancellation_restores_signing_verification_and_pool_reuse() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let path = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let pin = SecretString::from("12345678");
    let fixture = Pkcs11::new(&path).unwrap();
    fixture
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = fixture
        .get_slots_with_initialized_token()
        .unwrap()
        .into_iter()
        .find(|&slot| fixture.get_token_info(slot).unwrap().label() == "kdf-test")
        .unwrap();
    let session = fixture.open_rw_session(slot).unwrap();
    session.login(UserType::User, Some(&pin)).unwrap();
    let label = "stream-ec";
    let public = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Id(label.as_bytes().to_vec()),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Verify(true),
        Attribute::EcParams(vec![6, 8, 42, 134, 72, 206, 61, 3, 1, 7]),
    ];
    let private = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Id(label.as_bytes().to_vec()),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];
    session
        .generate_key_pair(&Mechanism::EccKeyPairGen, &public, &private)
        .unwrap();
    session.close().unwrap();
    fixture.finalize().unwrap();
    let module = Module::load(&path).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let pool = SessionPool::new(token, SessionMode::ReadOnly, NonZeroUsize::new(1).unwrap());
    let mut lease = pool
        .try_acquire(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    let generation = lease.generation();
    let key = PrivateKeyRef::new(
        format!("pkcs11:token=kdf-test;object={label};type=private")
            .parse()
            .unwrap(),
    )
    .unwrap();
    let public = PublicKeyRef::new(
        format!("pkcs11:token=kdf-test;object={label};type=public")
            .parse()
            .unwrap(),
    )
    .unwrap();
    let parameters = SignatureParameters {
        algorithm: SignatureAlgorithm::Ecdsa,
        digest: DigestAlgorithm::Sha256,
        pss: None,
    };
    for hashing in [HashingPolicy::TokenOnly, HashingPolicy::SoftwareOnly] {
        let policy = SigningPolicy {
            hashing,
            ..Default::default()
        };
        let mut operation = lease
            .session()
            .start_signing(&key, parameters, &policy, None)
            .unwrap();
        operation.update(b"cancel this message").unwrap();
        operation.cancel().unwrap();
        lease.session().info().unwrap();
        let mut operation = lease
            .session()
            .start_verification(&public, parameters, &policy)
            .unwrap();
        operation.update(b"cancel this verification").unwrap();
        operation.cancel().unwrap();
        let mut operation = lease
            .session()
            .start_signing(&key, parameters, &policy, None)
            .unwrap();
        operation.update(b"new ").unwrap();
        operation.update(b"message").unwrap();
        let signature = operation.finish().unwrap();
        let mut operation = lease
            .session()
            .start_verification(&public, parameters, &policy)
            .unwrap();
        operation.update(b"new message").unwrap();
        operation.finish(&signature).unwrap();
        lease
            .session()
            .verify(
                &public,
                &VerifyRequest {
                    parameters: parameters.request(SignInput::Message(b"new message")),
                    signature: &signature,
                },
                &policy,
            )
            .unwrap();
        lease.session().info().unwrap();
    }
    drop(lease);
    let lease = pool.try_acquire(Authentication::None).unwrap();
    assert_eq!(lease.generation(), generation);
    drop(lease);
    pool.close().unwrap();
    module.finalize().unwrap();
}
