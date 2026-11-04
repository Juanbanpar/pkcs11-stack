// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent FIPS 204 HashML-DSA verification with RustCrypto public keys.
use ml_dsa::{
    EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature, VerifyingKey,
};
use pkcs11_client::*;
use secrecy::SecretString;
use sha2::{Digest, Sha512};
use std::{
    io::{self, Read},
    num::NonZeroUsize,
    path::PathBuf,
};
struct Chunks<'a> {
    bytes: &'a [u8],
    interrupted: bool,
    maximum: usize,
}
impl<'a> Chunks<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            interrupted: false,
            maximum: 0,
        }
    }
}
impl Read for Chunks<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.maximum = self.maximum.max(out.len());
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let length = self.bytes.len().min(out.len()).min(3071);
        out[..length].copy_from_slice(&self.bytes[..length]);
        self.bytes = &self.bytes[length..];
        Ok(length)
    }
}

fn verify<P: MlDsaParams>(bytes: &[u8], context: &[u8], digest: &[u8; 64], sig: &[u8]) {
    verify_hash::<P>(bytes, context, digest, 3, sig);
}
fn verify_hash<P: MlDsaParams>(bytes: &[u8], context: &[u8], digest: &[u8], oid: u8, sig: &[u8]) {
    let key = VerifyingKey::<P>::decode(&EncodedVerifyingKey::<P>::try_from(bytes).unwrap());
    // FIPS 204 Algorithm 5: 0x01 || context length || context || DER SHA-512 OID || PH(M).
    let mut encoded = vec![1, context.len().try_into().unwrap()];
    encoded.extend_from_slice(context);
    encoded.extend_from_slice(&[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, oid,
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
                        if matches!(input, HashMlDsaInput::Message(_)) {
                            let parameters = HashMlDsaParameters {
                                parameter_set,
                                context,
                                hedging,
                            };
                            assert!(
                                client
                                    .hash_ml_dsa_streaming_capabilities(&private, auth())
                                    .unwrap()
                                    .can_sign
                            );
                            assert!(
                                client
                                    .hash_ml_dsa_verification_capabilities(&public, auth())
                                    .unwrap()
                                    .can_stream
                            );
                            let generation =
                                client.pool().try_acquire(auth()).unwrap().generation();
                            let mut reader = Chunks::new(message);
                            let streamed = client
                                .sign_hash_ml_dsa_reader(
                                    &private,
                                    parameters,
                                    &policy,
                                    auth(),
                                    context_pin(),
                                    &mut reader,
                                )
                                .unwrap();
                            assert_eq!(reader.maximum, 65536);
                            assert!(reader.bytes.is_empty());
                            match parameter_set {
                                MlDsaParameterSet::MlDsa44 => {
                                    verify::<MlDsa44>(raw, context, &digest, &streamed)
                                }
                                MlDsaParameterSet::MlDsa65 => {
                                    verify::<MlDsa65>(raw, context, &digest, &streamed)
                                }
                                MlDsaParameterSet::MlDsa87 => {
                                    verify::<MlDsa87>(raw, context, &digest, &streamed)
                                }
                            }
                            client
                                .verify_hash_ml_dsa(&public, &request, &streamed, auth())
                                .unwrap();
                            client
                                .verify_hash_ml_dsa_reader(
                                    &public,
                                    parameters,
                                    &streamed,
                                    auth(),
                                    &mut Chunks::new(message),
                                )
                                .unwrap();
                            let mut changed = streamed.clone();
                            changed[0] ^= 1;
                            assert!(matches!(
                                client.verify_hash_ml_dsa_reader(
                                    &public,
                                    parameters,
                                    &changed,
                                    auth(),
                                    &mut Chunks::new(message)
                                ),
                                Err(Error::SignatureMismatch)
                            ));
                            assert_eq!(
                                client.pool().try_acquire(auth()).unwrap().generation(),
                                generation
                            );
                            if hedging == MlDsaHedging::Deterministic {
                                assert_eq!(sig, streamed);
                                std::fs::write(
                                    root.join(format!(
                                        "hash-stream-{index}-{}-{}.sig",
                                        context.len(),
                                        message.len()
                                    )),
                                    &streamed,
                                )
                                .unwrap();
                            }
                            if context == b"context"
                                && message == b"abc"
                                && hedging == MlDsaHedging::Deterministic
                            {
                                let mut lease = client.pool().try_acquire(auth()).unwrap();
                                let session = lease.session();
                                let mut sign = session
                                    .start_hash_ml_dsa_signing(
                                        &private,
                                        parameters,
                                        &policy,
                                        context_pin(),
                                    )
                                    .unwrap();
                                sign.update(b"a").unwrap();
                                sign.cancel().unwrap();
                                let mut sign = session
                                    .start_hash_ml_dsa_signing(
                                        &private,
                                        parameters,
                                        &policy,
                                        context_pin(),
                                    )
                                    .unwrap();
                                sign.update(b"abc").unwrap();
                                let next = sign.finish().unwrap();
                                assert_eq!(next, sig);
                                let mut verify = session
                                    .start_hash_ml_dsa_verification(&public, parameters)
                                    .unwrap();
                                verify.update(b"a").unwrap();
                                verify.cancel().unwrap();
                                let mut verify = session
                                    .start_hash_ml_dsa_verification(&public, parameters)
                                    .unwrap();
                                verify.update(b"abc").unwrap();
                                verify.finish(&sig).unwrap();
                                drop(lease);
                                assert_eq!(
                                    client.pool().try_acquire(auth()).unwrap().generation(),
                                    generation
                                );
                            }
                        }
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

#[test]
#[ignore = "requires tools/test-kem-hkdf.sh with ML-DSA enabled"]
fn hash_ml_dsa_fixed_output_profiles_independent_signatures_and_streams() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=kdf-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let auth = || Authentication::User(Pin::Value(&pin));
    let sets = [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ];
    let mut management = provider
        .management(&token, SessionMode::ReadWrite, auth())
        .unwrap();
    for (index, set) in sets.into_iter().enumerate() {
        management
            .generate_ml_dsa_key_pair(
                set,
                &[0xE2, index as u8],
                b"HashML-DSA profiles",
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
    let large: Vec<_> = (0..1_000_003).map(|i| (i % 251) as u8).collect();
    for (index, set) in sets.into_iter().enumerate() {
        let private = PrivateKeyRef::new(
            format!("pkcs11:token=kdf-test;id=%E2%{index:02X};type=private")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let public = PublicKeyRef::new(
            format!("pkcs11:token=kdf-test;id=%E2%{index:02X};type=public")
                .parse()
                .unwrap(),
        )
        .unwrap();
        let spki = client.export_ml_dsa_public_key(&public, auth()).unwrap();
        std::fs::write(root.join(format!("hash-profile-{index}.der")), &spki).unwrap();
        use x509_cert::der::Decode;
        let decoded = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&spki).unwrap();
        let raw = decoded.subject_public_key.as_bytes().unwrap();
        let context_pin = || (index == 1).then_some(Pin::Value(&pin));
        for (hash_index, (hash, oid)) in [
            (DigestAlgorithm::Sha224, 4),
            (DigestAlgorithm::Sha256, 1),
            (DigestAlgorithm::Sha384, 2),
            (DigestAlgorithm::Sha512, 3),
            (DigestAlgorithm::Sha3_224, 7),
            (DigestAlgorithm::Sha3_256, 8),
            (DigestAlgorithm::Sha3_384, 9),
            (DigestAlgorithm::Sha3_512, 10),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                client
                    .hash_ml_dsa_streaming_capabilities_with_hash(&private, hash, auth())
                    .unwrap()
                    .can_sign
            );
            assert!(
                client
                    .hash_ml_dsa_verification_capabilities_with_hash(&public, hash, auth())
                    .unwrap()
                    .can_stream
            );
            for context in [&[][..], b"context", &[0xA5; 255]] {
                for message in [&[][..], b"abc", large.as_slice()] {
                    let digest = match hash {
                        DigestAlgorithm::Sha224 => sha2::Sha224::digest(message).to_vec(),
                        DigestAlgorithm::Sha256 => sha2::Sha256::digest(message).to_vec(),
                        DigestAlgorithm::Sha384 => sha2::Sha384::digest(message).to_vec(),
                        DigestAlgorithm::Sha512 => sha2::Sha512::digest(message).to_vec(),
                        DigestAlgorithm::Sha3_224 => sha3::Sha3_224::digest(message).to_vec(),
                        DigestAlgorithm::Sha3_256 => sha3::Sha3_256::digest(message).to_vec(),
                        DigestAlgorithm::Sha3_384 => sha3::Sha3_384::digest(message).to_vec(),
                        DigestAlgorithm::Sha3_512 => sha3::Sha3_512::digest(message).to_vec(),
                    };
                    for hedging in [
                        MlDsaHedging::Required,
                        MlDsaHedging::Preferred,
                        MlDsaHedging::Deterministic,
                    ] {
                        let parameters = HashMlDsaParameters {
                            parameter_set: set,
                            context,
                            hedging,
                        }
                        .with_hash(hash);
                        let policy = MlDsaSigningPolicy::default();
                        let request = parameters.request(message);
                        let caps = client
                            .hash_ml_dsa_capabilities(&private, request.input.mode(), auth())
                            .unwrap();
                        caps.validate(&request, &policy).unwrap();
                        let message_sig = client
                            .sign_hash_ml_dsa(&private, &request, &policy, auth(), context_pin())
                            .unwrap();
                        let prehashed = HashMlDsaRequest {
                            input: HashMlDsaInput::Digest {
                                hash,
                                bytes: &digest,
                            },
                            ..request
                        };
                        let digest_sig = client
                            .sign_hash_ml_dsa(&private, &prehashed, &policy, auth(), context_pin())
                            .unwrap();
                        let mut reader = Chunks::new(message);
                        let stream_sig = client
                            .sign_hash_ml_dsa_reader(
                                &private,
                                parameters,
                                &policy,
                                auth(),
                                context_pin(),
                                &mut reader,
                            )
                            .unwrap();
                        assert_eq!(reader.maximum, 65536);
                        assert!(reader.bytes.is_empty());
                        for sig in [&message_sig, &digest_sig, &stream_sig] {
                            match set {
                                MlDsaParameterSet::MlDsa44 => {
                                    verify_hash::<MlDsa44>(raw, context, &digest, oid, sig)
                                }
                                MlDsaParameterSet::MlDsa65 => {
                                    verify_hash::<MlDsa65>(raw, context, &digest, oid, sig)
                                }
                                MlDsaParameterSet::MlDsa87 => {
                                    verify_hash::<MlDsa87>(raw, context, &digest, oid, sig)
                                }
                            }
                            client
                                .verify_hash_ml_dsa(&public, &request, sig, auth())
                                .unwrap();
                            client
                                .verify_hash_ml_dsa(&public, &prehashed, sig, auth())
                                .unwrap();
                            client
                                .verify_hash_ml_dsa_reader(
                                    &public,
                                    parameters,
                                    sig,
                                    auth(),
                                    &mut Chunks::new(message),
                                )
                                .unwrap();
                        }
                        let generation = client.pool().try_acquire(auth()).unwrap().generation();
                        let mut changed = stream_sig.clone();
                        changed[0] ^= 1;
                        assert!(matches!(
                            client.verify_hash_ml_dsa_reader(
                                &public,
                                parameters,
                                &changed,
                                auth(),
                                &mut Chunks::new(message)
                            ),
                            Err(Error::SignatureMismatch)
                        ));
                        assert_eq!(
                            client.pool().try_acquire(auth()).unwrap().generation(),
                            generation
                        );
                        if hedging == MlDsaHedging::Deterministic {
                            let other = match hash {
                                DigestAlgorithm::Sha224 => DigestAlgorithm::Sha3_224,
                                DigestAlgorithm::Sha256 => DigestAlgorithm::Sha3_256,
                                DigestAlgorithm::Sha384 => DigestAlgorithm::Sha3_384,
                                DigestAlgorithm::Sha512 => DigestAlgorithm::Sha3_512,
                                DigestAlgorithm::Sha3_224 => DigestAlgorithm::Sha224,
                                DigestAlgorithm::Sha3_256 => DigestAlgorithm::Sha256,
                                DigestAlgorithm::Sha3_384 => DigestAlgorithm::Sha384,
                                DigestAlgorithm::Sha3_512 => DigestAlgorithm::Sha512,
                            };
                            let wrong_hash = HashMlDsaRequest {
                                input: HashMlDsaInput::Digest {
                                    hash: other,
                                    bytes: &digest,
                                },
                                ..request
                            };
                            assert!(matches!(
                                client.verify_hash_ml_dsa(
                                    &public,
                                    &wrong_hash,
                                    &digest_sig,
                                    auth()
                                ),
                                Err(Error::SignatureMismatch)
                            ));
                            assert_eq!(
                                client.pool().try_acquire(auth()).unwrap().generation(),
                                generation
                            );
                            assert_eq!(message_sig, digest_sig);
                            assert_eq!(message_sig, stream_sig);
                            std::fs::write(
                                root.join(format!(
                                    "hash-profile-{index}-{hash_index}-{}-{}.sig",
                                    context.len(),
                                    message.len()
                                )),
                                &stream_sig,
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
