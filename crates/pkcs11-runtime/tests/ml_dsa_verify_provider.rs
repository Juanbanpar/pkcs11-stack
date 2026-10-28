// SPDX-License-Identifier: MIT OR Apache-2.0
//! Required real 3.2 signature-first verification and same-pool-session reuse.
use pkcs11_runtime::*;
use secrecy::SecretString;
use std::num::NonZeroUsize;
#[test]
#[ignore = "requires the disposable Kryoptic runner with ML-DSA enabled"]
fn signature_first_verification_mismatches_cancellation_and_pool_reuse() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    assert_eq!(module.interface().version, InterfaceVersion::V3_2);
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let pin = SecretString::from("12345678");
    let sets = [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ];
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, parameter) in sets.into_iter().enumerate() {
        session
            .generate_ml_dsa_key_pair(
                parameter,
                &[0xD6, index as u8],
                b"signature-first-runtime",
                false,
            )
            .unwrap();
    }
    session.close().unwrap();
    let pool = SessionPool::new(token, SessionMode::ReadOnly, NonZeroUsize::new(1).unwrap());
    let mut lease = pool
        .try_acquire(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    let generation = lease.generation();
    for (index, parameter_set) in sets.into_iter().enumerate() {
        let private = PrivateKeyRef::new(
            format!("pkcs11:token=kdf-test;id=%D6%{index:02X};type=private")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let public = PublicKeyRef::new(
            format!("pkcs11:token=kdf-test;id=%D6%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let session = lease.session();
        let caps = session.ml_dsa_verification_capabilities(&public).unwrap();
        assert!(caps.can_verify && caps.can_stream);
        assert_eq!(caps.parameter_set, parameter_set);
        for context in [&[][..], &[0xA5; 255]] {
            for hedging in [
                MlDsaHedging::Preferred,
                MlDsaHedging::Required,
                MlDsaHedging::Deterministic,
            ] {
                let parameters = MlDsaParameters {
                    parameter_set,
                    context,
                    hedging,
                };
                for message in [&[][..], b"original message"] {
                    let request = parameters.request(message);
                    let signature = session
                        .sign_ml_dsa(&private, &request, &MlDsaSigningPolicy::default(), None)
                        .unwrap();
                    session
                        .verify_ml_dsa_signature_first(&public, &request, &signature)
                        .unwrap();
                    let mut operation = session
                        .start_ml_dsa_verification(&public, parameters, &signature)
                        .unwrap();
                    for chunk in message.chunks(3) {
                        operation.update(chunk).unwrap();
                    }
                    operation.finish().unwrap();
                    let mut altered = signature.clone();
                    altered[0] ^= 1;
                    assert!(matches!(
                        session.verify_ml_dsa_signature_first(&public, &request, &altered),
                        Err(Error::SignatureMismatch)
                    ));
                    let mut operation = session
                        .start_ml_dsa_verification(&public, parameters, &altered)
                        .unwrap();
                    operation.update(message).unwrap();
                    assert!(matches!(operation.finish(), Err(Error::SignatureMismatch)));
                    let mut operation = session
                        .start_ml_dsa_verification(&public, parameters, &signature)
                        .unwrap();
                    operation.update(b"cancel this verification").unwrap();
                    operation.cancel().unwrap();
                    session
                        .verify_ml_dsa_signature_first(&public, &request, &signature)
                        .unwrap();
                    session.info().unwrap();
                }
            }
        }
    }
    drop(lease);
    let lease = pool.try_acquire(Authentication::None).unwrap();
    assert_eq!(lease.generation(), generation);
    drop(lease);
    pool.close().unwrap();
    module.finalize().unwrap();
}
