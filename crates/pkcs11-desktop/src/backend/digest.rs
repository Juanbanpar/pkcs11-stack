// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{BackendError, Registry, ResourceId, browse::read_session};
use pkcs11_client::{DigestMode, HashAlgorithm};
use std::{fs::File, path::Path};

impl Registry {
    pub(super) fn digest_algorithms(
        &self,
        module: ResourceId,
        token: ResourceId,
    ) -> Result<Vec<HashAlgorithm>, BackendError> {
        let (index, uri) = self.location(module, token)?;
        let module = &self.modules[index];
        read_session(module, &uri, module.read_mode(token)?, |session| {
            session
                .digest_algorithms(DigestMode::Multipart)
                .map_err(|e| BackendError::from(&e))
        })
    }
    pub(super) fn digest_file(
        &self,
        module: ResourceId,
        token: ResourceId,
        algorithm: HashAlgorithm,
        path: &Path,
    ) -> Result<Vec<u8>, BackendError> {
        let (index, uri) = self.location(module, token)?;
        let module = &self.modules[index];
        let mut input = File::open(path).map_err(|_| BackendError::CryptoRead)?;
        read_session(module, &uri, module.read_mode(token)?, |session| {
            session.digest_reader(algorithm, &mut input).map_err(|e| {
                if matches!(e, pkcs11_client::Error::DigestInput) {
                    BackendError::CryptoRead
                } else {
                    BackendError::from(&e)
                }
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_digest_target_does_not_open_an_input() {
        assert_eq!(
            Registry::default().digest_file(
                ResourceId(1),
                ResourceId(2),
                HashAlgorithm::Sha256,
                Path::new("/must-not-open")
            ),
            Err(BackendError::UnknownModule)
        );
    }
    #[test]
    #[ignore = "requires the isolated SoftHSM runner"]
    fn software_token_file_digest_rechecks_capabilities_and_recovers_after_read_failure() {
        assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
        let root = std::path::PathBuf::from(std::env::var_os("PKCS11_CLIENT_TEST_DIR").unwrap());
        let mut registry = Registry::default();
        let module = registry
            .load(&std::path::PathBuf::from(
                std::env::var_os("PKCS11_TEST_MODULE").unwrap(),
            ))
            .unwrap();
        let token = registry.modules[0]
            .entry
            .tokens
            .iter()
            .find(|entry| entry.label == "client-test")
            .unwrap()
            .id;
        assert!(
            registry
                .digest_algorithms(module, token)
                .unwrap()
                .contains(&HashAlgorithm::Sha256)
        );
        let input = root.join("desktop-digest-input");
        std::fs::write(&input, b"abc").unwrap();
        let digest = registry
            .digest_file(module, token, HashAlgorithm::Sha256, &input)
            .unwrap();
        assert_eq!(
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(
            registry
                .digest_file(module, token, HashAlgorithm::Sha256, &root)
                .is_err()
        );
        assert_eq!(
            registry
                .digest_file(module, token, HashAlgorithm::Sha256, &input)
                .unwrap(),
            digest
        );
        assert_eq!(
            registry.digest_file(
                module,
                token,
                HashAlgorithm::Sha256,
                &root.join("missing-digest-input")
            ),
            Err(BackendError::CryptoRead)
        );
        registry.close().unwrap();
    }
}
