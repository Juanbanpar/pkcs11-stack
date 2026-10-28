// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unknown metadata remains inspectable without granting typed crypto support.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_runtime::{Attribute, AttributeType, Error, Module, SessionMode};
#[test]
fn mixed_discovery_preserves_opaque_scalars_and_known_objects() {
    for fault in 0..=2 {
        let fixture = MetadataModule::new(fault);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let raw = match fault {
            0 => 0x7fff0001,
            1 => 0x80000001,
            _ => *cryptoki::types::Ulong::new(!0),
        };
        {
            let objects = session.find_objects(&[Attribute::Token(true)]).unwrap();
            assert_eq!(objects.len(), 8);
            let attrs = [
                AttributeType::Class,
                AttributeType::KeyType,
                AttributeType::CertificateType,
                AttributeType::ProfileId,
                AttributeType::ValidationType,
                AttributeType::ValidationAuthorityType,
            ];
            let reads: Vec<_> = objects
                .iter()
                .map(|o| o.read_attributes(&attrs).unwrap())
                .collect();
            assert!(matches!(reads[0].expose_values(), [Attribute::Class(v)] if **v == raw));
            for read in &reads[1..4] {
                assert!(
                    read.expose_values()
                        .iter()
                        .any(|a| matches!(a,Attribute::KeyType(v) if **v == raw))
                );
            }
            assert!(
                reads[4]
                    .expose_values()
                    .iter()
                    .any(|a| matches!(a,Attribute::CertificateType(v) if **v == raw))
            );
            assert!(
                reads[5]
                    .expose_values()
                    .contains(&Attribute::Class(pkcs11_runtime::ObjectClass::DATA))
            );
            assert!(
                reads[6]
                    .expose_values()
                    .iter()
                    .any(|a| matches!(a,Attribute::ValidationType(v) if **v == raw))
            );
            assert!(
                reads[6]
                    .expose_values()
                    .iter()
                    .any(|a| matches!(a,Attribute::ValidationAuthorityType(v) if **v == raw))
            );
            assert!(
                reads[7]
                    .expose_values()
                    .iter()
                    .any(|a| matches!(a,Attribute::ProfileId(v) if *v.as_ref() == raw))
            );
        }
        session.info().unwrap();
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
#[test]
fn malformed_scalars_and_native_errors_invalidate_the_session() {
    let cases = [
        (1, AttributeType::Class),
        (4, AttributeType::KeyType),
        (5, AttributeType::CertificateType),
        (8, AttributeType::ProfileId),
        (7, AttributeType::ValidationType),
        (7, AttributeType::ValidationAuthorityType),
    ];
    for fault in 3..=15 {
        let fixture = MetadataModule::new(fault);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let (id, kind) = cases[usize::from((fault - 3) % 6)];
        {
            let objects = session
                .find_objects(&[Attribute::Id(vec![if fault == 15 { 1 } else { id }])])
                .unwrap();
            assert_eq!(objects.len(), 1);
            assert!(
                objects[0]
                    .read_attributes(&[if fault == 15 {
                        AttributeType::Class
                    } else {
                        kind
                    }])
                    .is_err()
            );
        }
        assert!(matches!(session.info(), Err(Error::Closed)));
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}

#[test]
fn opaque_key_types_do_not_enable_typed_operations() {
    use pkcs11_runtime::{
        AesGcmOperation, DigestAlgorithm, MacOperation, PrivateKeyRef, PublicKeyRef, SignInput,
        SignRequest, SignatureAlgorithm, SigningPolicy, VerifyRequest,
    };
    for fault in 0..=2 {
        let fixture = MetadataModule::new(fault);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let private =
            PrivateKeyRef::new("pkcs11:token=cmac;id=%02;type=private".parse().unwrap()).unwrap();
        let public =
            PublicKeyRef::new("pkcs11:token=cmac;id=%03;type=public".parse().unwrap()).unwrap();
        let secret = pkcs11_runtime::ObjectRef::new(
            "pkcs11:token=cmac;id=%04;type=secret-key".parse().unwrap(),
        )
        .unwrap();
        let request = SignRequest {
            algorithm: SignatureAlgorithm::RsaPkcs1,
            digest: DigestAlgorithm::Sha256,
            input: SignInput::Message(b"message"),
            pss: None,
        };
        assert!(matches!(
            session.sign(&private, &request, &SigningPolicy::default(), None),
            Err(Error::UnsupportedSigning("key type"))
        ));
        assert!(matches!(
            session.verify(
                &public,
                &VerifyRequest {
                    parameters: request,
                    signature: &[0; 256]
                },
                &SigningPolicy::default()
            ),
            Err(Error::UnsupportedVerification("key type"))
        ));
        for operation in [MacOperation::Generate, MacOperation::Verify] {
            assert!(matches!(
                session.hmac_options(&secret, operation),
                Err(Error::UnsupportedMac)
            ));
            assert!(matches!(
                session.aes_cmac_options(&secret, operation),
                Err(Error::UnsupportedMac)
            ));
        }
        for operation in [AesGcmOperation::Encrypt, AesGcmOperation::Decrypt] {
            assert!(matches!(
                session.aes_gcm_capabilities(&secret, operation),
                Err(Error::UnsupportedAesGcm)
            ));
        }
        assert!(matches!(
            session.kbkdf_capabilities(&secret),
            Err(Error::UnsupportedKeyOperation)
        ));
        assert!(session.hkdf_options(&secret).unwrap().is_empty());
        session.info().unwrap();
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
