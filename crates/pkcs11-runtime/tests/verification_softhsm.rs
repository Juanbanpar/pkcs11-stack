// SPDX-License-Identifier: MIT OR Apache-2.0
//! Token-side RSA/ECDSA verification on disposable SoftHSM.
//!
//! Signing uses the same private keys as the existing signing suite; verification
//! is performed by the token with the independent public-key object.

use pkcs11_runtime::{
    Authentication, Error, Function, Module, Pin, PrivateKeyRef, PssParameters, PublicKeyRef,
    SessionMode, SignInput, SignRequest, SignatureAlgorithm, SigningPolicy, VerifyRequest,
};
use secrecy::SecretString;
use sha2::{Digest, Sha256};

fn private(token: &str, object: &str) -> PrivateKeyRef {
    PrivateKeyRef::new(
        format!("pkcs11:token={token};object={object};type=private")
            .parse()
            .unwrap(),
    )
    .unwrap()
}

fn public(token: &str, object: &str) -> PublicKeyRef {
    PublicKeyRef::new(
        format!("pkcs11:token={token};object={object};type=public")
            .parse()
            .unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn token_verifies_rsa_and_ecdsa_signatures() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let module = Module::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=client-test".parse().unwrap())
        .unwrap();
    let pin = SecretString::from("12345678");
    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    let policy = SigningPolicy::default();
    let message = b"pkcs11-stack token verification test";

    for (algorithm, private_object, public_object, pss) in [
        (SignatureAlgorithm::RsaPkcs1, "rsa", "rsa", None),
        (
            SignatureAlgorithm::RsaPss,
            "rsa",
            "rsa",
            Some(PssParameters {
                mgf_digest: pkcs11_runtime::DigestAlgorithm::Sha256,
                salt_len: 32,
            }),
        ),
        (SignatureAlgorithm::Ecdsa, "p256", "p256", None),
    ] {
        let request = SignRequest {
            algorithm,
            digest: pkcs11_runtime::DigestAlgorithm::Sha256,
            input: SignInput::Message(message),
            pss,
        };
        let key = private("client-test", private_object);
        let public_key = public("client-test", public_object);
        let signature = session.sign(&key, &request, &policy, None).unwrap();
        session
            .verify(
                &public_key,
                &VerifyRequest {
                    parameters: request,
                    signature: &signature,
                },
                &policy,
            )
            .unwrap();

        let mut tampered = signature.clone();
        tampered[0] ^= 1;
        assert!(matches!(
            session.verify(
                &public_key,
                &VerifyRequest {
                    parameters: request,
                    signature: &tampered,
                },
                &policy,
            ),
            Err(Error::SignatureMismatch)
        ));
        // A mismatch terminates the operation but leaves the session usable.
        session.info().unwrap();

        // Signature-first verification is gated by the selected interface.
        let digest = Sha256::digest(message);
        let signature_first = SignRequest {
            algorithm,
            digest: pkcs11_runtime::DigestAlgorithm::Sha256,
            input: SignInput::Digest(&digest),
            pss,
        };
        match session.verify_signature(&public_key, &signature_first, &signature) {
            Ok(()) => {}
            Err(Error::UnsupportedVerification(_)) => {
                // Providers may expose a non-null 3.2 stub that returns
                // CKR_FUNCTION_NOT_SUPPORTED. Availability of a function-list
                // entry is therefore not proof of execution support.
                let _ = module.supports_function(Function::VerifySignatureInit);
            }
            Err(error) => panic!("signature-first verification failed: {error}"),
        }
    }
}
