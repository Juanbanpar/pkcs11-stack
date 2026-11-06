// SPDX-License-Identifier: MIT OR Apache-2.0
//! Client SLH-DSA operations agree with runtime signatures and public SPKI.
use pkcs11_client::*;
use secrecy::SecretString;
use std::{num::NonZeroUsize, path::PathBuf};
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh after the SLH-DSA runtime test"]
fn client_slh_dsa_profiles_generation_permissions_and_runtime_agreement() {
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
    let policy = SlhDsaSigningPolicy::default();
    for (index, parameter_set) in SlhDsaParameterSet::ALL.into_iter().enumerate() {
        let private = PrivateKeyRef::new(
            format!("pkcs11:token=kdf-test;object=slh-dsa-runtime-{index};type=private")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let public = PublicKeyRef::new(
            format!("pkcs11:token=kdf-test;object=slh-dsa-runtime-{index};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let caps = client.slh_dsa_capabilities(&private, auth()).unwrap();
        assert_eq!(caps.parameter_set, parameter_set);
        assert!(caps.can_sign);
        assert_eq!(caps.always_authenticate, index == 1);
        assert_eq!(
            client.export_slh_dsa_public_key(&public, auth()).unwrap(),
            std::fs::read(root.join(format!("slh-{index}.der"))).unwrap()
        );
        let request = SlhDsaRequest {
            parameter_set,
            message: b"SLH-DSA original message\0\xff",
            context: b"domain",
            hedging: SlhDsaHedging::Deterministic,
        };
        let expected = std::fs::read(root.join(format!("slh-{index}-0.signature"))).unwrap();
        let signature = client
            .sign_slh_dsa(
                &private,
                &request,
                &policy,
                auth(),
                (index == 1).then_some(Pin::Value(&pin)),
            )
            .unwrap();
        assert_eq!(signature, expected);
        client
            .verify_slh_dsa(&public, &request, &signature, auth())
            .unwrap();
        let bad = SlhDsaRequest {
            context: b"wrong context",
            ..request
        };
        assert!(matches!(
            client.verify_slh_dsa(&public, &bad, &signature, auth()),
            Err(Error::SignatureMismatch)
        ));
        client
            .verify_slh_dsa(&public, &request, &signature, auth())
            .unwrap();
        assert!(
            client
                .sign_slh_dsa(
                    &private,
                    &request,
                    &SlhDsaSigningPolicy {
                        parameter_sets: vec![]
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
        id: b"slh-client",
        label: b"SLH client generation",
        always_authenticate: false,
    };
    management.generate_slh_dsa_key_pair(&request).unwrap();
    assert!(management.generate_slh_dsa_key_pair(&request).is_err());
    management.close().unwrap();
    provider.finalize().unwrap();
}
