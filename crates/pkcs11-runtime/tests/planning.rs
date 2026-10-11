// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure capability/policy tests, requiring no module or software token.
use pkcs11_runtime::*;

fn rsa(mechanisms: &[MechanismType]) -> KeyCapabilities {
    KeyCapabilities {
        key: KeyKind::Rsa { bits: 2048 },
        can_sign: true,
        always_authenticate: false,
        allowed_mechanisms: None,
        mechanisms: mechanisms
            .iter()
            .map(|&mechanism| SigningMechanism {
                mechanism,
                can_sign: true,
                minimum_bits: 1024,
                maximum_bits: 4096,
            })
            .collect(),
    }
}
fn request(input: SignInput<'_>) -> SignRequest<'_> {
    SignRequest {
        algorithm: SignatureAlgorithm::RsaPkcs1,
        digest: DigestAlgorithm::Sha256,
        input,
        pss: None,
    }
}
#[test]
fn hashing_boundaries_are_explicit() {
    let key = rsa(&[MechanismType::RSA_PKCS, MechanismType::SHA256_RSA_PKCS]);
    let message = request(SignInput::Message(b"message"));
    let mut policy = SigningPolicy::default();
    assert_eq!(
        key.plan(&message, &policy).unwrap().hash_location(),
        HashLocation::Token
    );
    policy.hashing = HashingPolicy::SoftwareOnly;
    assert_eq!(
        key.plan(&message, &policy).unwrap().hash_location(),
        HashLocation::Software
    );
    let raw = rsa(&[MechanismType::RSA_PKCS]);
    policy.hashing = HashingPolicy::TokenOnly;
    assert!(raw.plan(&message, &policy).is_err());
    policy.hashing = HashingPolicy::AllowSoftware;
    assert_eq!(
        raw.plan(&message, &policy).unwrap().hash_location(),
        HashLocation::Software
    );
    // TokenOnly restricts message hashing; a caller digest is already outside the token.
    policy.hashing = HashingPolicy::TokenOnly;
    assert_eq!(
        raw.plan(&request(SignInput::Digest(&[0; 32])), &policy)
            .unwrap()
            .hash_location(),
        HashLocation::Caller
    );
    assert!(
        rsa(&[MechanismType::SHA256_RSA_PKCS])
            .plan(&request(SignInput::Digest(&[0; 32])), &policy)
            .is_err()
    );
}
#[test]
fn constraints_are_intersected_not_inferred_from_names() {
    let base = rsa(&[MechanismType::RSA_PKCS, MechanismType::SHA256_RSA_PKCS]);
    let req = request(SignInput::Message(b"m"));
    let mut k = base.clone();
    k.can_sign = false;
    assert!(k.plan(&req, &SigningPolicy::default()).is_err());
    k = base.clone();
    k.allowed_mechanisms = Some(vec![MechanismType::RSA_PKCS]);
    assert!(k.plan(&req, &SigningPolicy::default()).is_err());
    k.allowed_mechanisms = Some(vec![]);
    assert!(k.plan(&req, &SigningPolicy::default()).is_ok());
    k = base.clone();
    k.mechanisms[1].can_sign = false;
    assert!(k.plan(&req, &SigningPolicy::default()).is_err());
    k = base.clone();
    k.mechanisms[1].minimum_bits = 3072;
    assert!(k.plan(&req, &SigningPolicy::default()).is_err());
    k = base.clone();
    k.mechanisms[1].maximum_bits = 1024;
    assert!(k.plan(&req, &SigningPolicy::default()).is_err());
    k = base.clone();
    k.key = KeyKind::Rsa { bits: 1024 };
    assert!(k.plan(&req, &SigningPolicy::default()).is_err());
    k.key = KeyKind::Ec(NamedCurve::P256);
    assert!(k.plan(&req, &SigningPolicy::default()).is_err());
    let mut policy = SigningPolicy::default();
    policy.algorithms.clear();
    assert!(base.plan(&req, &policy).is_err());
    policy = SigningPolicy::default();
    policy.digests.clear();
    assert!(base.plan(&req, &policy).is_err());
}
#[test]
fn pss_parameters_and_encoding_bounds_are_enforced() {
    let key = rsa(&[
        MechanismType::RSA_PKCS_PSS,
        MechanismType::SHA256_RSA_PKCS_PSS,
    ]);
    let mut req = request(SignInput::Message(b"m"));
    req.algorithm = SignatureAlgorithm::RsaPss;
    assert!(key.plan(&req, &SigningPolicy::default()).is_err());
    for salt_len in [0, 20, 32, 222] {
        req.pss = Some(PssParameters {
            mgf_digest: DigestAlgorithm::Sha384,
            salt_len,
        });
        assert!(key.plan(&req, &SigningPolicy::default()).is_ok());
    }
    for salt_len in [223, usize::MAX] {
        req.pss.as_mut().unwrap().salt_len = salt_len;
        assert!(key.plan(&req, &SigningPolicy::default()).is_err());
    }
    req.pss.as_mut().unwrap().salt_len = 32;
    let mut policy = SigningPolicy {
        digests: vec![DigestAlgorithm::Sha256],
        ..Default::default()
    };
    assert!(key.plan(&req, &policy).is_err());
    req.algorithm = SignatureAlgorithm::RsaPkcs1;
    assert!(
        rsa(&[MechanismType::SHA256_RSA_PKCS])
            .plan(&req, &SigningPolicy::default())
            .is_err()
    );
    let mut zero = key.clone();
    zero.key = KeyKind::Rsa { bits: 0 };
    policy.minimum_rsa_bits = 0;
    assert!(zero.plan(&req, &policy).is_err());
}
#[test]
fn all_digest_lengths_and_mechanism_mappings() {
    for (digest, len, combined) in [
        (DigestAlgorithm::Sha256, 32, MechanismType::SHA256_RSA_PKCS),
        (DigestAlgorithm::Sha384, 48, MechanismType::SHA384_RSA_PKCS),
        (DigestAlgorithm::Sha512, 64, MechanismType::SHA512_RSA_PKCS),
    ] {
        let k = rsa(&[MechanismType::RSA_PKCS, combined]);
        let mut req = request(SignInput::Message(b"m"));
        req.digest = digest;
        assert_eq!(
            k.plan(&req, &SigningPolicy::default()).unwrap().mechanism(),
            combined
        );
        let good = vec![1; len];
        req.input = SignInput::Digest(&good);
        assert!(k.plan(&req, &SigningPolicy::default()).is_ok());
        let bad = vec![1; len - 1];
        req.input = SignInput::Digest(&bad);
        assert!(k.plan(&req, &SigningPolicy::default()).is_err());
    }
}
#[test]
fn always_authenticate_never_silently_skips_login() {
    let mut k = rsa(&[MechanismType::RSA_PKCS, MechanismType::SHA256_RSA_PKCS]);
    k.always_authenticate = true;
    assert!(
        k.plan(
            &request(SignInput::Message(b"m")),
            &SigningPolicy::default()
        )
        .unwrap()
        .context_authentication()
    );
    assert!(
        k.plan(
            &request(SignInput::Digest(&[0; 32])),
            &SigningPolicy::default()
        )
        .is_err()
    );
    let policy = SigningPolicy {
        hashing: HashingPolicy::SoftwareOnly,
        ..Default::default()
    };
    assert!(k.plan(&request(SignInput::Message(b"m")), &policy).is_err());
}
#[test]
fn ec_curve_size_and_token_raw_mechanisms() {
    for curve in [NamedCurve::P256, NamedCurve::P384, NamedCurve::P521] {
        let mut key = rsa(&[MechanismType::ECDSA]);
        key.key = KeyKind::Ec(curve);
        key.mechanisms[0].minimum_bits = 256;
        key.mechanisms[0].maximum_bits = 521;
        let req = SignRequest {
            algorithm: SignatureAlgorithm::Ecdsa,
            ..request(SignInput::Message(b"m"))
        };
        assert!(key.plan(&req, &SigningPolicy::default()).is_err());
        let policy = SigningPolicy {
            hashing: HashingPolicy::AllowSoftware,
            ..Default::default()
        };
        assert_eq!(
            key.plan(&req, &policy).unwrap().mechanism(),
            MechanismType::ECDSA
        );
        let forbidden_curve = SigningPolicy {
            curves: vec![],
            ..policy.clone()
        };
        assert!(key.plan(&req, &forbidden_curve).is_err());
        key.always_authenticate = true;
        assert!(key.plan(&req, &policy).is_err());
    }
}
#[test]
fn combined_ec_supports_context_authentication_but_raw_ec_does_not() {
    for curve in [NamedCurve::P256, NamedCurve::P384, NamedCurve::P521] {
        for (digest, combined) in [
            (DigestAlgorithm::Sha256, MechanismType::ECDSA_SHA256),
            (DigestAlgorithm::Sha384, MechanismType::ECDSA_SHA384),
            (DigestAlgorithm::Sha512, MechanismType::ECDSA_SHA512),
        ] {
            let mut key = rsa(&[MechanismType::ECDSA, combined]);
            key.key = KeyKind::Ec(curve);
            key.always_authenticate = true;
            for mechanism in &mut key.mechanisms {
                mechanism.minimum_bits = 256;
                mechanism.maximum_bits = 521;
            }
            let mut req = SignRequest {
                algorithm: SignatureAlgorithm::Ecdsa,
                digest,
                ..request(SignInput::Message(b"context-authenticated message"))
            };
            for hashing in [HashingPolicy::TokenOnly, HashingPolicy::AllowSoftware] {
                let policy = SigningPolicy {
                    hashing,
                    ..Default::default()
                };
                let plan = key.plan(&req, &policy).unwrap();
                assert_eq!(plan.mechanism(), combined);
                assert_eq!(plan.hash_location(), HashLocation::Token);
                assert!(plan.context_authentication());
            }
            let policy = SigningPolicy {
                hashing: HashingPolicy::SoftwareOnly,
                ..Default::default()
            };
            assert!(key.plan(&req, &policy).is_err());
            let hashed = vec![0; digest.output_len()];
            req.input = SignInput::Digest(&hashed);
            assert!(key.plan(&req, &SigningPolicy::default()).is_err());
        }
    }
}
#[test]
fn typed_references_and_inputs_keep_identity_and_redaction() {
    assert!(PrivateKeyRef::new("pkcs11:serial=x;id=%00%FF;type=private".parse().unwrap()).is_ok());
    assert!(PrivateKeyRef::new("pkcs11:serial=x;id=x;type=public".parse().unwrap()).is_err());
    assert!(PrivateKeyRef::new("pkcs11:serial=x;id=x".parse().unwrap()).is_err());
    assert!(PublicKeyRef::new("pkcs11:serial=x;id=x;type=public".parse().unwrap()).is_ok());
    assert!(CertificateRef::new("pkcs11:serial=x;id=x;type=cert".parse().unwrap()).is_ok());
    let req = request(SignInput::Message(b"signing-canary"));
    assert!(!format!("{req:?}").contains("signing-canary"));
}
