// SPDX-License-Identifier: MIT OR Apache-2.0
use pkcs11_runtime::{
    DigestAlgorithm as Digest, KeyCapabilities, KeyKind, NamedCurve, PssParameters, SignInput,
    SignRequest, SignatureAlgorithm, SigningPolicy,
};
use rustls::{SignatureScheme, crypto::CryptoProvider};

pub(crate) const PREFERENCE: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];
pub(crate) fn request(
    scheme: SignatureScheme,
    key: KeyKind,
    message: &[u8],
) -> Option<SignRequest<'_>> {
    use SignatureScheme::*;
    let (algorithm, digest) = match (scheme, key) {
        (RSA_PSS_SHA256, KeyKind::Rsa { .. }) => (SignatureAlgorithm::RsaPss, Digest::Sha256),
        (RSA_PSS_SHA384, KeyKind::Rsa { .. }) => (SignatureAlgorithm::RsaPss, Digest::Sha384),
        (RSA_PSS_SHA512, KeyKind::Rsa { .. }) => (SignatureAlgorithm::RsaPss, Digest::Sha512),
        (RSA_PKCS1_SHA256, KeyKind::Rsa { .. }) => (SignatureAlgorithm::RsaPkcs1, Digest::Sha256),
        (RSA_PKCS1_SHA384, KeyKind::Rsa { .. }) => (SignatureAlgorithm::RsaPkcs1, Digest::Sha384),
        (RSA_PKCS1_SHA512, KeyKind::Rsa { .. }) => (SignatureAlgorithm::RsaPkcs1, Digest::Sha512),
        (ECDSA_NISTP256_SHA256, KeyKind::Ec(NamedCurve::P256)) => {
            (SignatureAlgorithm::Ecdsa, Digest::Sha256)
        }
        (ECDSA_NISTP384_SHA384, KeyKind::Ec(NamedCurve::P384)) => {
            (SignatureAlgorithm::Ecdsa, Digest::Sha384)
        }
        (ECDSA_NISTP521_SHA512, KeyKind::Ec(NamedCurve::P521)) => {
            (SignatureAlgorithm::Ecdsa, Digest::Sha512)
        }
        _ => return None,
    };
    Some(SignRequest {
        algorithm,
        digest,
        input: SignInput::Message(message),
        pss: (algorithm == SignatureAlgorithm::RsaPss).then_some(PssParameters {
            mgf_digest: digest,
            salt_len: digest.output_len(),
        }),
    })
}
pub(crate) fn choose(
    offered: &[SignatureScheme],
    caps: &KeyCapabilities,
    policy: &SigningPolicy,
    provider: &CryptoProvider,
) -> Option<SignatureScheme> {
    let public_algorithm = match caps.key {
        KeyKind::Rsa { .. } => rustls_pki_types::alg_id::RSA_ENCRYPTION,
        KeyKind::Ec(NamedCurve::P256) => rustls_pki_types::alg_id::ECDSA_P256,
        KeyKind::Ec(NamedCurve::P384) => rustls_pki_types::alg_id::ECDSA_P384,
        KeyKind::Ec(NamedCurve::P521) => rustls_pki_types::alg_id::ECDSA_P521,
    };
    PREFERENCE.iter().copied().find(|scheme| {
        offered.contains(scheme)
            && provider
                .signature_verification_algorithms
                .mapping
                .iter()
                .any(|(s, a)| {
                    s == scheme && a.iter().any(|v| v.public_key_alg_id() == public_algorithm)
                })
            && request(*scheme, caps.key, b"").is_some_and(|r| caps.plan(&r, policy).is_ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::format_signature;
    use pkcs11_runtime::{HashingPolicy, MechanismType, SigningMechanism};
    #[test]
    fn schemes_require_matching_key_curve_and_explicit_pss() {
        for (scheme, digest) in [
            (SignatureScheme::RSA_PSS_SHA256, Digest::Sha256),
            (SignatureScheme::RSA_PSS_SHA384, Digest::Sha384),
            (SignatureScheme::RSA_PSS_SHA512, Digest::Sha512),
        ] {
            let r = request(scheme, KeyKind::Rsa { bits: 2048 }, b"message").unwrap();
            assert_eq!(
                r.pss,
                Some(PssParameters {
                    mgf_digest: digest,
                    salt_len: digest.output_len()
                })
            );
            assert!(matches!(r.input, SignInput::Message(b"message")));
        }
        assert!(
            request(
                SignatureScheme::ECDSA_NISTP256_SHA256,
                KeyKind::Ec(NamedCurve::P384),
                b""
            )
            .is_none()
        );
        assert!(request(SignatureScheme::ED25519, KeyKind::Ec(NamedCurve::P256), b"").is_none());
        assert!(
            request(
                SignatureScheme::RSA_PKCS1_SHA1,
                KeyKind::Rsa { bits: 2048 },
                b""
            )
            .is_none()
        );
    }
    #[test]
    fn selection_intersects_policy_provider_and_capabilities() {
        let provider = rustls::crypto::ring::default_provider();
        let mut caps = KeyCapabilities {
            key: KeyKind::Ec(NamedCurve::P256),
            can_sign: true,
            always_authenticate: false,
            allowed_mechanisms: None,
            mechanisms: vec![SigningMechanism {
                mechanism: MechanismType::ECDSA,
                can_sign: true,
                minimum_bits: 256,
                maximum_bits: 521,
            }],
        };
        let mut policy = SigningPolicy {
            hashing: HashingPolicy::SoftwareOnly,
            ..Default::default()
        };
        assert_eq!(
            choose(PREFERENCE, &caps, &policy, &provider),
            Some(SignatureScheme::ECDSA_NISTP256_SHA256)
        );
        assert!(
            choose(
                &[SignatureScheme::RSA_PSS_SHA256],
                &caps,
                &policy,
                &provider
            )
            .is_none()
        );
        policy.curves.clear();
        assert!(choose(PREFERENCE, &caps, &policy, &provider).is_none());
        policy = SigningPolicy {
            hashing: HashingPolicy::SoftwareOnly,
            ..Default::default()
        };
        caps.always_authenticate = true;
        assert!(choose(PREFERENCE, &caps, &policy, &provider).is_none());
        caps.always_authenticate = false;
        caps.can_sign = false;
        assert!(choose(PREFERENCE, &caps, &policy, &provider).is_none());
        caps.can_sign = true;
        let mut no_verifier = provider;
        no_verifier.signature_verification_algorithms.mapping = &[];
        assert!(choose(PREFERENCE, &caps, &policy, &no_verifier).is_none());
        // TLS 1.2 mappings can advertise the scheme with a different EC curve.
        // The scheme alone does not prove this provider can verify our P-256 key.
        static P384_ONLY: &[(
            SignatureScheme,
            &[&dyn rustls_pki_types::SignatureVerificationAlgorithm],
        )] = &[(
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[webpki::ring::ECDSA_P384_SHA256],
        )];
        no_verifier.signature_verification_algorithms.mapping = P384_ONLY;
        assert!(choose(PREFERENCE, &caps, &policy, &no_verifier).is_none());
    }
    #[test]
    fn ecdsa_encoding_is_canonical_and_width_checked() {
        let mut raw = vec![0; 64];
        raw[31] = 1;
        raw[32] = 0x80;
        let encoded = format_signature(KeyKind::Ec(NamedCurve::P256), raw).unwrap();
        assert_eq!(&encoded[..7], &[0x30, 38, 2, 1, 1, 2, 33]);
        assert_eq!(&encoded[7..9], &[0, 0x80]);
        let encoded = format_signature(KeyKind::Ec(NamedCurve::P521), vec![1; 132]).unwrap();
        assert_eq!(&encoded[..3], &[0x30, 0x81, 136]);
        assert!(format_signature(KeyKind::Ec(NamedCurve::P256), vec![0; 64]).is_err());
        assert!(format_signature(KeyKind::Ec(NamedCurve::P384), vec![1; 64]).is_err());
        assert_eq!(
            format_signature(KeyKind::Rsa { bits: 2048 }, vec![1; 256]).unwrap(),
            vec![1; 256]
        );
    }
}
