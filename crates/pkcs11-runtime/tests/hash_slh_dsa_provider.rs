// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixed-output HashSLH-DSA, protected keys and independent FIPS 205 message encoding.
use pkcs11_runtime::*;
use secrecy::SecretString;
use sha2::Digest;
use std::{path::PathBuf, process::Command};
fn digest(hash: DigestAlgorithm, bytes: &[u8]) -> Vec<u8> {
    match hash {
        DigestAlgorithm::Sha224 => sha2::Sha224::digest(bytes).to_vec(),
        DigestAlgorithm::Sha256 => sha2::Sha256::digest(bytes).to_vec(),
        DigestAlgorithm::Sha384 => sha2::Sha384::digest(bytes).to_vec(),
        DigestAlgorithm::Sha512 => sha2::Sha512::digest(bytes).to_vec(),
        DigestAlgorithm::Sha3_224 => sha3::Sha3_224::digest(bytes).to_vec(),
        DigestAlgorithm::Sha3_256 => sha3::Sha3_256::digest(bytes).to_vec(),
        DigestAlgorithm::Sha3_384 => sha3::Sha3_384::digest(bytes).to_vec(),
        DigestAlgorithm::Sha3_512 => sha3::Sha3_512::digest(bytes).to_vec(),
    }
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh with SLH-DSA enabled"]
fn hash_slh_dsa_fixed_hashes_parameter_sets_domains_and_protected_keys() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let pin = SecretString::from("12345678");
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    let policy = HashSlhDsaSigningPolicy {
        allow_reduced_strength: true,
        ..Default::default()
    };
    let mut interop = vec![];
    for (index, parameter_set) in SlhDsaParameterSet::ALL.into_iter().enumerate() {
        let hash = policy.hashes[index % 8];
        let id = [0x76, index as u8];
        let label = format!("hash-slh-dsa-runtime-{index}");
        let private = PrivateKeyRef::new(
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
        let generation = SlhDsaKeyPairRequest {
            parameter_set,
            id: &id,
            label: label.as_bytes(),
            always_authenticate: index == 1,
        };
        session.generate_hash_slh_dsa_key_pair(&generation).unwrap();
        assert!(matches!(
            session.generate_hash_slh_dsa_key_pair(&generation),
            Err(Error::InvalidParameters(_))
        ));
        assert!(!session.slh_dsa_capabilities(&private).unwrap().can_sign);
        assert!(session.slh_dsa_public_key(&public).is_err());
        let object = session.resolve(private.as_object_ref()).unwrap();
        let metadata = object
            .read_attributes(&[
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::AlwaysSensitive,
                AttributeType::NeverExtractable,
                AttributeType::AllowedMechanisms,
            ])
            .unwrap();
        let expected = [
            MechanismType::HASH_SLH_DSA,
            MechanismType::HASH_SLH_DSA_SHA224,
            MechanismType::HASH_SLH_DSA_SHA256,
            MechanismType::HASH_SLH_DSA_SHA384,
            MechanismType::HASH_SLH_DSA_SHA512,
            MechanismType::HASH_SLH_DSA_SHA3_224,
            MechanismType::HASH_SLH_DSA_SHA3_256,
            MechanismType::HASH_SLH_DSA_SHA3_384,
            MechanismType::HASH_SLH_DSA_SHA3_512,
        ];
        for attribute in [
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::AlwaysSensitive(true),
            Attribute::NeverExtractable(true),
            Attribute::AllowedMechanisms(expected.to_vec()),
        ] {
            assert!(
                metadata.expose_values().contains(&attribute),
                "{index}: {attribute:?}"
            );
        }
        assert!(matches!(
            object
                .attribute_info(&[AttributeType::Value])
                .unwrap()
                .as_slice(),
            [AttributeInfo::Sensitive]
        ));
        let public_object = session.resolve(public.as_object_ref()).unwrap();
        let allowed = public_object
            .read_attributes(&[AttributeType::AllowedMechanisms])
            .unwrap();
        assert_eq!(
            allowed.expose_values(),
            [Attribute::AllowedMechanisms(expected.to_vec())]
        );
        // Provider SPKI is used only to load the raw public material for EVP internal verification.
        let spki = public_object
            .read_attributes_bounded(&[AttributeType::PublicKeyInfo], 256)
            .unwrap();
        let [Attribute::PublicKeyInfo(der)] = spki.expose_values() else {
            panic!("public SPKI")
        };
        std::fs::write(root.join(format!("hslh-{index}.der")), der).unwrap();
        let mut read_only = token.open_session(SessionMode::ReadOnly).unwrap();
        assert!(matches!(
            read_only.generate_hash_slh_dsa_key_pair(&generation),
            Err(Error::ReadWriteRequired)
        ));
        for (case, (message, context, hedging)) in [
            (
                b"HashSLH-DSA original message\0\xff".as_slice(),
                b"domain".as_slice(),
                SlhDsaHedging::Deterministic,
            ),
            (b"".as_slice(), b"".as_slice(), SlhDsaHedging::Preferred),
            (
                b"HashSLH-DSA original message\0\xff".as_slice(),
                &[0xa5; 255],
                SlhDsaHedging::Required,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let hashed = digest(hash, message);
            let request = HashSlhDsaRequest {
                parameter_set,
                input: HashSlhDsaInput::Message { hash, message },
                context,
                hedging,
            };
            let prehashed = HashSlhDsaRequest {
                input: HashSlhDsaInput::Digest {
                    hash,
                    bytes: &hashed,
                },
                ..request
            };
            let context_pin = || (index == 1).then_some(Pin::Value(&pin));
            let signature = read_only
                .sign_hash_slh_dsa(&private, &request, &policy, context_pin())
                .unwrap();
            let pre_signature = read_only
                .sign_hash_slh_dsa(&private, &prehashed, &policy, context_pin())
                .unwrap();
            if case == 0 {
                assert_eq!(signature, pre_signature);
            }
            for sig in [&signature, &pre_signature] {
                read_only
                    .verify_hash_slh_dsa(&public, &request, sig)
                    .unwrap();
                read_only
                    .verify_hash_slh_dsa(&public, &prehashed, sig)
                    .unwrap();
            }
            for bad in [
                HashSlhDsaRequest {
                    context: b"wrong context",
                    ..request
                },
                HashSlhDsaRequest {
                    input: HashSlhDsaInput::Message {
                        hash,
                        message: b"tampered",
                    },
                    ..request
                },
            ] {
                assert!(matches!(
                    read_only.verify_hash_slh_dsa(&public, &bad, &signature),
                    Err(Error::SignatureMismatch)
                ));
            }
            let other_hash = policy.hashes[(index % 8 + 4) % 8];
            let wrong_hash = HashSlhDsaRequest {
                input: HashSlhDsaInput::Digest {
                    hash: other_hash,
                    bytes: &hashed,
                },
                ..request
            };
            assert!(matches!(
                read_only.verify_hash_slh_dsa(&public, &wrong_hash, &signature),
                Err(Error::SignatureMismatch)
            ));
            read_only
                .verify_hash_slh_dsa(&public, &request, &signature)
                .unwrap();
            let pure = SlhDsaRequest {
                parameter_set,
                message,
                context,
                hedging,
            };
            assert!(
                read_only
                    .sign_slh_dsa(
                        &private,
                        &pure,
                        &SlhDsaSigningPolicy::default(),
                        context_pin()
                    )
                    .is_err()
            );
            assert_eq!(read_only.info().unwrap().device_error(), 0);
            for (suffix, value) in [
                ("signature", signature.as_slice()),
                ("digest", hashed.as_slice()),
                ("context", context),
            ] {
                std::fs::write(root.join(format!("hslh-{index}-{case}.{suffix}")), value).unwrap();
            }
            // FIPS 205 Algorithm 23: 01 || ctx_len || ctx || DER hash OID || PH(M).
            let oid = [4, 1, 2, 3, 7, 8, 9, 10][index % 8];
            let mut mprime = vec![1, u8::try_from(context.len()).unwrap()];
            mprime.extend_from_slice(context);
            mprime.extend_from_slice(&[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, oid,
            ]);
            mprime.extend_from_slice(&hashed);
            let path = root.join(format!("hslh-{index}-{case}.mprime"));
            std::fs::write(&path, &mprime).unwrap();
            interop.push((index, case, path));
        }
        read_only.close().unwrap();
    }
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
    let prefix = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap())
        .canonicalize()
        .unwrap()
        .parent()
        .unwrap()
        .join("openssl");
    let helper = root.join("hash-slh-verify");
    let output = Command::new("cc")
        .args(["-std=c99", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(prefix.join("include"))
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/slh_dsa_openssl.c"))
        .arg(prefix.join("lib/libcrypto.a"))
        .args(["-ldl", "-lpthread", "-o"])
        .arg(&helper)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let empty = root.join("hslh-empty.context");
    std::fs::write(&empty, []).unwrap();
    for (index, case, path) in interop {
        let verify = || {
            Command::new(&helper)
                .arg(root.join(format!("hslh-{index}.der")))
                .arg(root.join(format!("hslh-{index}-{case}.signature")))
                .arg(&path)
                .arg(&empty)
                .arg("raw")
                .output()
                .unwrap()
        };
        let output = verify();
        assert!(
            output.status.success(),
            "EVP {index}/{case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut bad = std::fs::read(&path).unwrap();
        bad[0] = 0;
        std::fs::write(&path, bad).unwrap();
        assert!(!verify().status.success(), "wrong domain must fail EVP");
    }
}
