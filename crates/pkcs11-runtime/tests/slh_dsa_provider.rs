// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure SLH-DSA provider profiles, protected key policy and independent EVP verification.
use pkcs11_runtime::*;
use secrecy::SecretString;
use std::{path::PathBuf, process::Command};
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh with SLH-DSA enabled"]
fn pure_slh_dsa_profiles_contexts_hedging_and_protected_keys() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    assert_eq!(
        token.slh_dsa_generation_options().unwrap(),
        SlhDsaParameterSet::ALL
    );
    let pin = SecretString::from("12345678");
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, parameter_set) in SlhDsaParameterSet::ALL.into_iter().enumerate() {
        let id = [0x75, index as u8];
        let label = format!("slh-dsa-runtime-{index}");
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
        session.generate_slh_dsa_key_pair(&generation).unwrap();
        assert!(matches!(
            session.generate_slh_dsa_key_pair(&generation),
            Err(Error::InvalidParameters(_))
        ));
        let key = session.slh_dsa_public_key(&public).unwrap();
        assert_eq!(key.as_bytes().len(), parameter_set.public_key_length());
        let object = session.resolve(private.as_object_ref()).unwrap();
        let metadata = object
            .read_attributes(&[
                AttributeType::Token,
                AttributeType::Private,
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::AlwaysSensitive,
                AttributeType::NeverExtractable,
                AttributeType::Sign,
                AttributeType::Decrypt,
                AttributeType::Derive,
                AttributeType::Unwrap,
                AttributeType::AllowedMechanisms,
            ])
            .unwrap();
        for attr in [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::AlwaysSensitive(true),
            Attribute::NeverExtractable(true),
            Attribute::Sign(true),
            Attribute::Decrypt(false),
            Attribute::Derive(false),
            Attribute::Unwrap(false),
            Attribute::AllowedMechanisms(vec![MechanismType::SLH_DSA]),
        ] {
            assert!(
                metadata.expose_values().contains(&attr),
                "{parameter_set:?}: {attr:?}"
            );
        }
        assert!(matches!(
            object
                .attribute_info(&[AttributeType::Value])
                .unwrap()
                .as_slice(),
            [AttributeInfo::Sensitive]
        ));
        let mut read_only = token.open_session(SessionMode::ReadOnly).unwrap();
        assert!(matches!(
            read_only.generate_slh_dsa_key_pair(&generation),
            Err(Error::ReadWriteRequired)
        ));
        let policy = SlhDsaSigningPolicy::default();
        let mut signatures = vec![];
        for (case, (message, context, hedging)) in [
            (
                b"SLH-DSA original message\0\xff".as_slice(),
                b"domain".as_slice(),
                SlhDsaHedging::Deterministic,
            ),
            (b"".as_slice(), b"".as_slice(), SlhDsaHedging::Preferred),
            (
                b"SLH-DSA original message\0\xff".as_slice(),
                &[0xa5; 255],
                SlhDsaHedging::Required,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let request = SlhDsaRequest {
                parameter_set,
                message,
                context,
                hedging,
            };
            let context_pin = || (index == 1).then_some(Pin::Value(&pin));
            let signature = read_only
                .sign_slh_dsa(&private, &request, &policy, context_pin())
                .unwrap();
            assert_eq!(signature.len(), parameter_set.signature_length());
            read_only
                .verify_slh_dsa(&public, &request, &signature)
                .unwrap();
            let bad = SlhDsaRequest {
                context: b"wrong context",
                ..request
            };
            assert!(matches!(
                read_only.verify_slh_dsa(&public, &bad, &signature),
                Err(Error::SignatureMismatch)
            ));
            read_only.info().unwrap();
            let mut tampered = signature.clone();
            tampered[0] ^= 1;
            assert!(matches!(
                read_only.verify_slh_dsa(&public, &request, &tampered),
                Err(Error::SignatureMismatch)
            ));
            read_only
                .verify_slh_dsa(&public, &request, &signature)
                .unwrap();
            for (suffix, value) in [
                ("signature", signature.as_slice()),
                ("message", message),
                ("context", context),
            ] {
                std::fs::write(root.join(format!("slh-{index}-{case}.{suffix}")), value).unwrap();
            }
            signatures.push(signature);
        }
        let request = SlhDsaRequest {
            parameter_set,
            message: b"SLH-DSA original message\0\xff",
            context: b"domain",
            hedging: SlhDsaHedging::Deterministic,
        };
        assert_eq!(
            read_only
                .sign_slh_dsa(
                    &private,
                    &request,
                    &policy,
                    (index == 1).then_some(Pin::Value(&pin))
                )
                .unwrap(),
            signatures[0]
        );
        read_only.close().unwrap();
        // Public SPKI only; no private value or seed is extracted for EVP checks.
        let object = session.resolve(public.as_object_ref()).unwrap();
        let spki = object
            .read_attributes_bounded(&[AttributeType::PublicKeyInfo], 256)
            .unwrap();
        let [Attribute::PublicKeyInfo(der)] = spki.expose_values() else {
            panic!("public SPKI")
        };
        std::fs::write(root.join(format!("slh-{index}.der")), der).unwrap();
    }
    session.close().unwrap();
    module.finalize().unwrap();
    // Compile and run the independent OpenSSL EVP adapter after checked cleanup.
    let prefix = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap())
        .canonicalize()
        .unwrap()
        .parent()
        .unwrap()
        .join("openssl");
    let helper = root.join("slh-verify");
    let result = Command::new("cc")
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
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for index in 0..12 {
        for case in 0..3 {
            let result = Command::new(&helper)
                .arg(root.join(format!("slh-{index}.der")))
                .arg(root.join(format!("slh-{index}-{case}.signature")))
                .arg(root.join(format!("slh-{index}-{case}.message")))
                .arg(root.join(format!("slh-{index}-{case}.context")))
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "OpenSSL {index}/{case}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}
