// SPDX-License-Identifier: MIT OR Apache-2.0
//! HashSLH-DSA client inputs agree with independently verified runtime signatures.
use pkcs11_client::*;
use secrecy::SecretString;
use std::{num::NonZeroUsize, path::PathBuf};
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh after the SLH-DSA runtime test"]
fn client_hash_slh_dsa_input_modes_generation_policy_and_runtime_agreement() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=kdf-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let auth = || Authentication::User(Pin::Value(&pin));
    assert_eq!(
        provider.slh_dsa_generation_options(&token).unwrap(),
        SlhDsaParameterSet::ALL
    );
    let client = provider
        .client(
            &token,
            NonZeroUsize::new(1).unwrap(),
            SigningPolicy::default(),
        )
        .unwrap();
    let policy = HashSlhDsaSigningPolicy {
        allow_reduced_strength: true,
        ..Default::default()
    };
    for (index, parameter_set) in SlhDsaParameterSet::ALL.into_iter().enumerate() {
        let private = PrivateKeyRef::new(
            format!("pkcs11:token=kdf-test;object=hash-slh-dsa-runtime-{index};type=private")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let public = PublicKeyRef::new(
            format!("pkcs11:token=kdf-test;object=hash-slh-dsa-runtime-{index};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let hash = policy.hashes[index % 8];
        let caps = client
            .hash_slh_dsa_capabilities(&private, HashSlhDsaMode::Message(hash), auth())
            .unwrap();
        assert_eq!(caps.parameter_set, parameter_set);
        assert!(caps.can_sign);
        assert_eq!(caps.always_authenticate, index == 1);
        assert!(client.export_slh_dsa_public_key(&public, auth()).is_err());
        let request = HashSlhDsaRequest {
            parameter_set,
            input: HashSlhDsaInput::Message {
                hash,
                message: b"HashSLH-DSA original message\0\xff",
            },
            context: b"domain",
            hedging: SlhDsaHedging::Deterministic,
        };
        let expected = std::fs::read(root.join(format!("hslh-{index}-0.signature"))).unwrap();
        let signature = client
            .sign_hash_slh_dsa(
                &private,
                &request,
                &policy,
                auth(),
                (index == 1).then_some(Pin::Value(&pin)),
            )
            .unwrap();
        assert_eq!(signature, expected);
        let digest = std::fs::read(root.join(format!("hslh-{index}-0.digest"))).unwrap();
        let prehashed = HashSlhDsaRequest {
            input: HashSlhDsaInput::Digest {
                hash,
                bytes: &digest,
            },
            ..request
        };
        assert_eq!(
            client
                .sign_hash_slh_dsa(
                    &private,
                    &prehashed,
                    &policy,
                    auth(),
                    (index == 1).then_some(Pin::Value(&pin))
                )
                .unwrap(),
            expected
        );
        client
            .verify_hash_slh_dsa(&public, &prehashed, &signature, auth())
            .unwrap();
        client
            .verify_hash_slh_dsa(&public, &request, &signature, auth())
            .unwrap();
        let bad = HashSlhDsaRequest {
            context: b"wrong context",
            ..request
        };
        assert!(matches!(
            client.verify_hash_slh_dsa(&public, &bad, &signature, auth()),
            Err(Error::SignatureMismatch)
        ));
        client
            .verify_hash_slh_dsa(&public, &request, &signature, auth())
            .unwrap();
        assert!(
            client
                .sign_hash_slh_dsa(
                    &private,
                    &request,
                    &HashSlhDsaSigningPolicy {
                        parameter_sets: vec![],
                        ..Default::default()
                    },
                    auth(),
                    None
                )
                .is_err()
        );
    }
    client.close().unwrap();
    let mut management = provider
        .management(&token, SessionMode::ReadWrite, auth())
        .unwrap();
    let request = SlhDsaKeyPairRequest {
        parameter_set: SlhDsaParameterSet::Shake128F,
        id: b"hash-slh-client",
        label: b"HashSLH client generation",
        always_authenticate: false,
    };
    management.generate_hash_slh_dsa_key_pair(&request).unwrap();
    assert!(management.generate_hash_slh_dsa_key_pair(&request).is_err());
    management.close().unwrap();
    provider.finalize().unwrap();
}
