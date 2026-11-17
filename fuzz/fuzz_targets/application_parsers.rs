// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use pkcs11_client::{
    AesGcmEnvelope, Certificate, CertificateDocument, EdDsaVerifyingKey, MlDsaVerifyingKey,
    MlKemPublicKey,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = AesGcmEnvelope::parse(data) {
        assert_eq!(&data[..7], b"P11GCM\x01");
        assert_eq!(envelope.nonce(), &data[7..19]);
        assert_eq!(envelope.ciphertext(), &data[19..]);
        assert!(envelope.ciphertext().len() >= 16);
    }
    if let Ok(document) = CertificateDocument::from_der(data.to_vec()) {
        assert_eq!(document.der(), data);
        assert!(CertificateDocument::from_der([data, &[0]].concat()).is_err());
    }
    let _ = Certificate::from_der(data.to_vec());
    let _ = MlDsaVerifyingKey::from_spki_der(data);
    if let Ok(key) = MlKemPublicKey::from_spki_der(data) {
        assert_eq!(key.to_spki_der().unwrap(), data);
        assert!(MlKemPublicKey::from_spki_der(&[data, &[0]].concat()).is_err());
    }
    if let Ok(key) = EdDsaVerifyingKey::from_spki_der(data) {
        assert_eq!(key.to_spki_der().unwrap(), data);
    }
});
