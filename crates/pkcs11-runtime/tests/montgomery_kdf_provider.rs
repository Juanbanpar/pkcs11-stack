// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 7748 shared secrets and independent multi-block SHA-2 KDF references.
#[path = "fixtures/montgomery_kdf_cases.rs"]
#[allow(dead_code)]
mod cases;
use pkcs11_runtime::{
    AesGcmEncryptRequest, AesKeySize, Attribute, AttributeInfo, AttributeType as A, Authentication,
    DigestAlgorithm, EcdhKdf, KbkdfOutput, KbkdfRequest, KeyType, Module, MontgomeryKdfRequest,
    MontgomeryNamedCurve as C, MontgomeryNamedPublicKey, MontgomeryOutput, ObjectClass, ObjectRef,
    Pin, Session, SessionMode, X448PublicKey, X25519PublicKey,
};
use secrecy::SecretString;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
fn reference(group: u8, curve: usize, id: u8, kind: &str) -> ObjectRef {
    ObjectRef::new(cases::uri(group, curve, id, kind).parse().unwrap()).unwrap()
}
fn expand<H: Digest>(z: &[u8], info: &[u8], nist: bool, length: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for counter in 1u32.. {
        let mut h = H::new();
        if nist {
            h.update(counter.to_be_bytes());
            h.update(z);
        } else {
            h.update(z);
            h.update(counter.to_be_bytes());
        }
        h.update(info);
        bytes.extend(h.finalize());
        if bytes.len() >= length {
            bytes.truncate(length);
            return bytes;
        }
    }
    unreachable!()
}
fn encrypt(session: &mut Session<'_>, key: &ObjectRef) -> Vec<u8> {
    session
        .encrypt_aes_gcm(
            key,
            &AesGcmEncryptRequest {
                nonce: &[6; 12],
                aad: b"Montgomery KDF test",
                plaintext: b"protected KDF proof",
            },
        )
        .unwrap()
}
fn proof(
    session: &mut Session<'_>,
    curve: usize,
    source: u8,
    output: usize,
    target: u8,
) -> Vec<u8> {
    let source = reference(0x4b, curve, source, "secret-key");
    if output >= 3 {
        return encrypt(session, &source);
    }
    session
        .derive_kbkdf(
            &source,
            &KbkdfRequest {
                digest: DigestAlgorithm::Sha512,
                kdf_label: b"Montgomery proof",
                context: b"v1",
                output: KbkdfOutput::Aes256,
                id: &[0xd9, 0x4b, curve as u8, target],
                label: b"Montgomery proof",
            },
        )
        .unwrap();
    let key = reference(0x4b, curve, target, "secret-key");
    let cipher = encrypt(session, &key);
    session.resolve(&key).unwrap().destroy().unwrap();
    cipher
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn sha2_kdfs_match_rfc_shared_values_for_all_exact_profiles_and_protected_outputs() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    let pin = SecretString::from("12345678");
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for curve in 0..4 {
        let (params, private, peer, shared) = cases::profile(curve);
        // Only these public RFC test fixtures use private-key import.
        session
            .create_object(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::EC_MONTGOMERY),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Derive(true),
                Attribute::AlwaysAuthenticate(false),
                Attribute::EcParams(params.to_vec()),
                Attribute::Value(private),
                Attribute::Id(vec![0xd9, 0x4b, curve as u8, 0]),
                Attribute::Label(b"RFC KDF base".to_vec()),
            ])
            .unwrap();
        std::fs::write(
            root.join(format!("montgomery-kdf-peer-{curve}")),
            cases::peer_input(curve),
        )
        .unwrap();
        for kdf in 0..8 {
            for output in 0..6 {
                let output_kind = cases::output(output);
                let length = output_kind.length().unwrap();
                let info = cases::info(output);
                let expected = match kdf % 4 {
                    0 => expand::<Sha224>(&shared, info, kdf >= 4, length),
                    1 => expand::<Sha256>(&shared, info, kdf >= 4, length),
                    2 => expand::<Sha384>(&shared, info, kdf >= 4, length),
                    _ => expand::<Sha512>(&shared, info, kdf >= 4, length),
                };
                let request = MontgomeryKdfRequest {
                    kdf: cases::kdf(kdf),
                    shared_info: info,
                    output: output_kind,
                    id: &[0xd9, 0x4b, curve as u8, 1],
                    label: b"derived KDF key",
                };
                let base = reference(0x4b, curve, 0, "private");
                let derive = |s: &mut Session<'_>| match curve {
                    0 => s.derive_x25519_with_kdf(
                        &base,
                        &X25519PublicKey::from_bytes(&peer).unwrap(),
                        &request,
                    ),
                    1 => s.derive_x448_with_kdf(
                        &base,
                        &X448PublicKey::from_bytes(&peer).unwrap(),
                        &request,
                    ),
                    _ => s.derive_named_montgomery_with_kdf(
                        &base,
                        &MontgomeryNamedPublicKey::from_bytes(
                            if curve == 2 {
                                C::Curve25519
                            } else {
                                C::Curve448
                            },
                            &peer,
                        )
                        .unwrap(),
                        &request,
                    ),
                };
                derive(&mut session).unwrap_or_else(|e| panic!("{curve}/{kdf}/{output}: {e:?}"));
                assert!(derive(&mut session).is_err()); // A duplicate never replaces the first output.
                let key = reference(0x4b, curve, 1, "secret-key");
                let object = session.resolve(&key).unwrap();
                let attrs = object
                    .read_attributes(&[
                        A::KeyType,
                        A::ValueLen,
                        A::Private,
                        A::Sensitive,
                        A::Extractable,
                        A::Derive,
                        A::Encrypt,
                        A::Decrypt,
                        A::Sign,
                        A::Verify,
                        A::Wrap,
                        A::Unwrap,
                    ])
                    .unwrap();
                for attr in [
                    Attribute::KeyType(if output >= 3 {
                        KeyType::AES
                    } else {
                        KeyType::GENERIC_SECRET
                    }),
                    Attribute::ValueLen(length.try_into().unwrap()),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Derive(output < 3),
                    Attribute::Encrypt(output >= 3),
                    Attribute::Decrypt(output >= 3),
                    Attribute::Sign(false),
                    Attribute::Verify(false),
                    Attribute::Wrap(false),
                    Attribute::Unwrap(false),
                ] {
                    assert!(attrs.expose_values().contains(&attr), "{attr:?}");
                }
                assert!(matches!(
                    object.attribute_info(&[A::Value]).unwrap().as_slice(),
                    [AttributeInfo::Sensitive]
                ));
                let cipher = proof(&mut session, curve, 1, output, 3);
                session
                    .create_object(&[
                        Attribute::Class(ObjectClass::SECRET_KEY),
                        Attribute::KeyType(if output >= 3 {
                            KeyType::AES
                        } else {
                            KeyType::GENERIC_SECRET
                        }),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Extractable(false),
                        Attribute::Derive(output < 3),
                        Attribute::Encrypt(output >= 3),
                        Attribute::Value(expected),
                        Attribute::Id(vec![0xd9, 0x4b, curve as u8, 2]),
                        Attribute::Label(b"KDF oracle".to_vec()),
                    ])
                    .unwrap();
                assert_eq!(
                    cipher,
                    proof(&mut session, curve, 2, output, 4),
                    "{curve}/{kdf}/{output}"
                );
                std::fs::write(root.join(cases::cipher_name(curve, kdf, output)), cipher).unwrap();
                for id in [1, 2] {
                    session
                        .resolve(&reference(0x4b, curve, id, "secret-key"))
                        .unwrap()
                        .destroy()
                        .unwrap();
                }
            }
        }
    }
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
