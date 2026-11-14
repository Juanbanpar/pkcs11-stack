// SPDX-License-Identifier: MIT OR Apache-2.0
//! Positive SLH-DSA, HashSLH-DSA, HashML-DSA and Montgomery coverage on an
//! unmodified Kryoptic build with `slhdsa`, `mldsa`, `mlkem` and `ecc_all`.

use pkcs11_runtime::{
    AesGcmDecryptRequest, AesGcmEncryptRequest, AesKeySize, Authentication, HashInput,
    HashMlDsaRequest, HashMlDsaSigningPolicy, HashSlhDsaRequest, HashSlhDsaSigningPolicy,
    MlDsaHedging, MlDsaParameterSet, Module, MontgomeryCurve, MontgomeryDerivation, MontgomeryKdf,
    MontgomeryOutput, ObjectRef, Pin, PrehashAlgorithm, PrivateKeyRef, PublicKeyRef, SessionMode,
    SlhDsaHedging, SlhDsaKeyPairRequest, SlhDsaParameterSet, SlhDsaRequest, SlhDsaSigningPolicy,
};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

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

fn secret(token: &str, object: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token={token};object={object};type=secret-key")
            .parse()
            .unwrap(),
    )
    .unwrap()
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 128);
    let mut encoded = vec![tag, body.len() as u8];
    encoded.extend_from_slice(body);
    encoded
}

fn slh_spki(parameter: SlhDsaParameterSet, key: &[u8]) -> Vec<u8> {
    let oid: &[u8] = match parameter {
        SlhDsaParameterSet::Sha2_128S => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14],
        SlhDsaParameterSet::Sha2_128F => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x15],
        SlhDsaParameterSet::Sha2_192S => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x16],
        SlhDsaParameterSet::Sha2_192F => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x17],
        SlhDsaParameterSet::Sha2_256S => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x18],
        SlhDsaParameterSet::Sha2_256F => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x19],
        SlhDsaParameterSet::Shake128S => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1a],
        SlhDsaParameterSet::Shake128F => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1b],
        SlhDsaParameterSet::Shake192S => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1c],
        SlhDsaParameterSet::Shake192F => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1d],
        SlhDsaParameterSet::Shake256S => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1e],
        SlhDsaParameterSet::Shake256F => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1f],
    };
    let algorithm = der(0x30, &der(0x06, oid));
    let mut bits = vec![0];
    bits.extend_from_slice(key);
    let mut body = algorithm;
    body.extend(der(0x03, &bits));
    der(0x30, &body)
}

fn openssl_verify_slh(
    root: &Path,
    parameter: SlhDsaParameterSet,
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) {
    let openssl = std::env::var_os("PKCS11_TEST_PQC_OPENSSL").unwrap_or_else(|| "openssl".into());
    let key = root.join("slh-public.der");
    let input = root.join("slh-message");
    let signature_path = root.join("slh-signature");
    std::fs::write(&key, slh_spki(parameter, public)).unwrap();
    std::fs::write(&input, message).unwrap();
    std::fs::write(&signature_path, signature).unwrap();
    let output = std::process::Command::new(openssl)
        .args([
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            key.to_str().unwrap(),
            "-keyform",
            "DER",
            "-rawin",
            "-in",
            input.to_str().unwrap(),
            "-sigfile",
            signature_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "OpenSSL SLH-DSA verification failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires tools/test-pqc-kryoptic.sh disposable store"]
fn slh_hash_pqc_and_montgomery_provider_workflows() {
    assert_eq!(
        std::env::var("PKCS11_TEST_PQC_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_PQC_DIR").unwrap());
    let pin = SecretString::from("12345678");
    let so = SecretString::from("87654321");
    let mut module = Module::load(std::env::var_os("PKCS11_TEST_PQC_MODULE").unwrap()).unwrap();
    let slots = module.slots(true).unwrap();
    assert_eq!(slots.len(), 1);
    module.initialize_token(slots[0], &so, "pqc-test").unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=pqc-test".parse().unwrap())
        .unwrap();
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::SecurityOfficer(Pin::Value(&so)))
        .unwrap();
    session.initialize_pin(&pin).unwrap();
    session.logout().unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();

    let slh_parameter = SlhDsaParameterSet::Sha2_128F;
    let slh_id = b"slh-pure";
    session
        .generate_slh_dsa_key_pair(&SlhDsaKeyPairRequest {
            parameter_set: slh_parameter,
            id: slh_id,
            label: b"slh-pure",
            always_authenticate: false,
        })
        .unwrap();
    let slh_private = private("pqc-test", "slh-pure");
    let slh_public = public("pqc-test", "slh-pure");
    let slh_caps = session.slh_dsa_capabilities(&slh_private).unwrap();
    assert_eq!(slh_caps.parameter_set, slh_parameter);
    assert!(slh_caps.can_sign);
    let slh_request = SlhDsaRequest {
        parameter_set: slh_parameter,
        message: b"positive SLH-DSA provider message",
        context: b"",
        hedging: SlhDsaHedging::Deterministic,
    };
    let slh_signature = session
        .sign_slh_dsa(
            &slh_private,
            &slh_request,
            &SlhDsaSigningPolicy::default(),
            None,
        )
        .unwrap();
    assert_eq!(slh_signature.len(), slh_parameter.signature_length());
    session
        .verify_slh_dsa(&slh_public, &slh_request, &slh_signature)
        .unwrap();
    let mut tampered = slh_signature.clone();
    tampered[0] ^= 1;
    assert!(matches!(
        session.verify_slh_dsa(&slh_public, &slh_request, &tampered),
        Err(pkcs11_runtime::Error::SignatureMismatch)
    ));
    let exported = session.slh_dsa_public_key(&slh_public).unwrap();
    openssl_verify_slh(
        &root,
        slh_parameter,
        exported.as_bytes(),
        slh_request.message,
        &slh_signature,
    );

    session
        .generate_hash_slh_dsa_key_pair(&SlhDsaKeyPairRequest {
            parameter_set: slh_parameter,
            id: b"slh-hash",
            label: b"slh-hash",
            always_authenticate: false,
        })
        .unwrap();
    let hash_slh_private = private("pqc-test", "slh-hash");
    let hash_slh_public = public("pqc-test", "slh-hash");
    let hash_slh_request = HashSlhDsaRequest {
        parameter_set: slh_parameter,
        input: HashInput::Message {
            hash: PrehashAlgorithm::Sha256,
            message: b"positive HashSLH-DSA provider message",
        },
        context: b"slh-context",
        hedging: SlhDsaHedging::Deterministic,
    };
    let hash_slh_signature = session
        .sign_hash_slh_dsa(
            &hash_slh_private,
            &hash_slh_request,
            &HashSlhDsaSigningPolicy::default(),
            None,
        )
        .unwrap();
    session
        .verify_hash_slh_dsa(&hash_slh_public, &hash_slh_request, &hash_slh_signature)
        .unwrap();
    let digest = Sha256::digest(hash_slh_request.input.bytes()).to_vec();
    let hash_slh_digest_request = HashSlhDsaRequest {
        input: HashInput::Digest {
            hash: PrehashAlgorithm::Sha256,
            bytes: &digest,
        },
        ..hash_slh_request
    };
    let digest_signature = session
        .sign_hash_slh_dsa(
            &hash_slh_private,
            &hash_slh_digest_request,
            &HashSlhDsaSigningPolicy::default(),
            None,
        )
        .unwrap();
    session
        .verify_hash_slh_dsa(
            &hash_slh_public,
            &hash_slh_digest_request,
            &digest_signature,
        )
        .unwrap();
    assert!(matches!(
        session.verify_hash_slh_dsa(
            &hash_slh_public,
            &hash_slh_request,
            &hash_slh_signature[..hash_slh_signature.len() - 1]
        ),
        Err(pkcs11_runtime::Error::SignatureMismatch)
    ));

    session
        .generate_ml_dsa_key_pair(MlDsaParameterSet::MlDsa44, b"ml-dsa", b"ml-dsa", false)
        .unwrap();
    let ml_dsa_private = private("pqc-test", "ml-dsa");
    let ml_dsa_public = public("pqc-test", "ml-dsa");
    let hash_ml_request = HashMlDsaRequest {
        parameter_set: MlDsaParameterSet::MlDsa44,
        input: HashInput::Message {
            hash: PrehashAlgorithm::Sha256,
            message: b"positive HashML-DSA provider message",
        },
        context: b"ml-context",
        hedging: MlDsaHedging::Deterministic,
    };
    let hash_ml_signature = session
        .sign_hash_ml_dsa(
            &ml_dsa_private,
            &hash_ml_request,
            &HashMlDsaSigningPolicy::default(),
            None,
        )
        .unwrap();
    session
        .verify_hash_ml_dsa(&ml_dsa_public, &hash_ml_request, &hash_ml_signature)
        .unwrap();
    let digest = Sha256::digest(hash_ml_request.input.bytes()).to_vec();
    let hash_ml_digest_request = HashMlDsaRequest {
        input: HashInput::Digest {
            hash: PrehashAlgorithm::Sha256,
            bytes: &digest,
        },
        ..hash_ml_request
    };
    let digest_signature = session
        .sign_hash_ml_dsa(
            &ml_dsa_private,
            &hash_ml_digest_request,
            &HashMlDsaSigningPolicy::default(),
            None,
        )
        .unwrap();
    session
        .verify_hash_ml_dsa(&ml_dsa_public, &hash_ml_digest_request, &digest_signature)
        .unwrap();
    assert!(matches!(
        session.verify_hash_ml_dsa(&ml_dsa_public, &hash_ml_request, &tampered),
        Err(pkcs11_runtime::Error::SignatureMismatch)
    ));

    for curve in [MontgomeryCurve::X25519, MontgomeryCurve::X448] {
        let a_label = format!("mont-a-{curve}");
        let b_label = format!("mont-b-{curve}");
        let a_private = private("pqc-test", &a_label);
        let b_private = private("pqc-test", &b_label);
        let a_public_ref = public("pqc-test", &a_label);
        let b_public_ref = public("pqc-test", &b_label);
        session
            .generate_montgomery_key_pair(curve, a_label.as_bytes(), a_label.as_bytes())
            .unwrap();
        session
            .generate_montgomery_key_pair(curve, b_label.as_bytes(), b_label.as_bytes())
            .unwrap();
        let a_public = session.montgomery_public_key(&a_public_ref).unwrap();
        let b_public = session.montgomery_public_key(&b_public_ref).unwrap();
        assert_eq!(a_public.curve(), curve);
        assert_eq!(a_public.as_bytes().len(), curve.public_key_length());
        let imported_id = format!("peer-a-{curve}");
        session
            .import_montgomery_public_key(&a_public, imported_id.as_bytes(), imported_id.as_bytes())
            .unwrap();
        let imported = session
            .montgomery_public_key(&public("pqc-test", &imported_id))
            .unwrap();
        assert_eq!(imported.as_bytes(), a_public.as_bytes());

        let a_secret = format!("derived-a-{curve}");
        let b_secret = format!("derived-b-{curve}");
        session
            .derive_montgomery(
                a_private.as_object_ref(),
                &MontgomeryDerivation {
                    peer: &b_public,
                    kdf: MontgomeryKdf::X963Sha256,
                    shared_info: b"pqc provider agreement",
                    output: MontgomeryOutput::Aes(AesKeySize::Bits128),
                    id: a_secret.as_bytes(),
                    label: a_secret.as_bytes(),
                },
            )
            .unwrap();
        session
            .derive_montgomery(
                b_private.as_object_ref(),
                &MontgomeryDerivation {
                    peer: &a_public,
                    kdf: MontgomeryKdf::X963Sha256,
                    shared_info: b"pqc provider agreement",
                    output: MontgomeryOutput::Aes(AesKeySize::Bits128),
                    id: b_secret.as_bytes(),
                    label: b_secret.as_bytes(),
                },
            )
            .unwrap();
        let a_key = secret("pqc-test", &a_secret);
        let b_key = secret("pqc-test", &b_secret);
        let nonce = [0x42; 12];
        let plaintext = b"Montgomery agreement produces the same AES key";
        let ciphertext = session
            .encrypt_aes_gcm(
                &a_key,
                &AesGcmEncryptRequest {
                    nonce: &nonce,
                    aad: b"agreement",
                    plaintext,
                },
            )
            .unwrap();
        let decrypted = session
            .decrypt_aes_gcm(
                &b_key,
                &AesGcmDecryptRequest {
                    nonce: &nonce,
                    aad: b"agreement",
                    ciphertext: &ciphertext,
                },
            )
            .unwrap();
        assert_eq!(decrypted.expose_secret(), plaintext);
    }
}
