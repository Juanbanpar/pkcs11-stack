// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent FIPS 204 HashML-DSA verification with RustCrypto public keys.
use ml_dsa::{
    EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature, VerifyingKey,
};
use pkcs11_client::*;
use secrecy::SecretString;
use sha2::{Digest, Sha512};
use std::{num::NonZeroUsize, path::PathBuf};

fn verify<P: MlDsaParams>(bytes: &[u8], context: &[u8], digest: &[u8; 64], sig: &[u8]) {
    let key = VerifyingKey::<P>::decode(&EncodedVerifyingKey::<P>::try_from(bytes).unwrap());
    // FIPS 204 Algorithm 5: 0x01 || context length || context || DER SHA-512 OID || PH(M).
    let mut encoded = vec![1, context.len().try_into().unwrap()];
    encoded.extend_from_slice(context);
    encoded.extend_from_slice(&[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    ]);
    encoded.extend_from_slice(digest);
    let signature = Signature::<P>::try_from(sig).unwrap();
    assert!(key.verify_internal(&encoded, &signature));
    encoded[0] = 0;
    assert!(!key.verify_internal(&encoded, &signature));
}

#[test]
#[ignore = "requires tools/test-kem-hkdf.sh with ML-DSA enabled"]
fn hash_ml_dsa_client_independent_verification_contexts_and_both_input_modes() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=kdf-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let auth = || Authentication::User(Pin::Value(&pin));
    let mut management = provider
        .management(&token, SessionMode::ReadWrite, auth())
        .unwrap();
    for (index, parameter_set) in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ]
    .into_iter()
    .enumerate()
    {
        management
            .generate_ml_dsa_key_pair(
                parameter_set,
                &[0xE1, index as u8],
                b"HashML-DSA client",
                index == 1,
            )
            .unwrap();
    }
    management.close().unwrap();
    let client = provider
        .client(
            &token,
            NonZeroUsize::new(1).unwrap(),
            SigningPolicy::default(),
        )
        .unwrap();
    let policy = MlDsaSigningPolicy::default();
    let data: Vec<u8> = (0..1_000_003).map(|i| (i % 251) as u8).collect();
    for (index, parameter_set) in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ]
    .into_iter()
    .enumerate()
    {
        let private = PrivateKeyRef::new(
            format!("pkcs11:token=kdf-test;id=%E1%{index:02X};type=private")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let public = PublicKeyRef::new(
            format!("pkcs11:token=kdf-test;id=%E1%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let context_pin = || (index == 1).then_some(Pin::Value(&pin));
        let der = client.export_ml_dsa_public_key(&public, auth()).unwrap();
        // The key is the raw byte-aligned BIT STRING from the existing RFC 9881 export.
        use x509_cert::der::Decode;
        let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&der).unwrap();
        let raw = spki.subject_public_key.as_bytes().unwrap();
        std::fs::write(root.join(format!("hash-mldsa-{index}.der")), &der).unwrap();
        for context in [&[][..], b"context", &[0xA5; 255]] {
            for message in [&[][..], b"abc", data.as_slice()] {
                let digest: [u8; 64] = Sha512::digest(message).into();
                for hedging in [
                    MlDsaHedging::Preferred,
                    MlDsaHedging::Required,
                    MlDsaHedging::Deterministic,
                ] {
                    let mut signatures = Vec::new();
                    for input in [
                        HashMlDsaInput::Message(message),
                        HashMlDsaInput::Sha512Digest(&digest),
                    ] {
                        let request = HashMlDsaRequest {
                            parameter_set,
                            input,
                            context,
                            hedging,
                        };
                        let caps = client
                            .hash_ml_dsa_capabilities(&private, input.mode(), auth())
                            .unwrap();
                        caps.validate(&request, &policy).unwrap();
                        let sig = client
                            .sign_hash_ml_dsa(&private, &request, &policy, auth(), context_pin())
                            .unwrap();
                        match parameter_set {
                            MlDsaParameterSet::MlDsa44 => {
                                verify::<MlDsa44>(raw, context, &digest, &sig)
                            }
                            MlDsaParameterSet::MlDsa65 => {
                                verify::<MlDsa65>(raw, context, &digest, &sig)
                            }
                            MlDsaParameterSet::MlDsa87 => {
                                verify::<MlDsa87>(raw, context, &digest, &sig)
                            }
                        }
                        client
                            .verify_hash_ml_dsa(&public, &request, &sig, auth())
                            .unwrap();
                        let mut changed = sig.clone();
                        changed[0] ^= 1;
                        assert!(matches!(
                            client.verify_hash_ml_dsa(&public, &request, &changed, auth()),
                            Err(Error::SignatureMismatch)
                        ));
                        client
                            .verify_hash_ml_dsa(&public, &request, &sig, auth())
                            .unwrap();
                        signatures.push(sig);
                    }
                    if hedging == MlDsaHedging::Deterministic {
                        assert_eq!(signatures[0], signatures[1]);
                        if context == b"context" && message == b"abc" {
                            std::fs::write(
                                root.join(format!("hash-mldsa-{index}.sig")),
                                &signatures[0],
                            )
                            .unwrap();
                        }
                    }
                }
            }
        }
    }
    client.close().unwrap();
    provider.finalize().unwrap();
}
