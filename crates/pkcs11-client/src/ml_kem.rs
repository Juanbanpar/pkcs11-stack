// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Error, ManagementSession, MlKemCapabilities, MlKemOperation, MlKemParameterSet, MlKemRequest,
    ObjectRef, Pkcs11Uri, PrivateKeyRef, Provider, PublicKeyRef,
};

impl Provider {
    /// Advertised ML-KEM generation parameters; template acceptance remains provider-specific.
    pub fn ml_kem_generation_options(
        &self,
        token: &Pkcs11Uri,
    ) -> Result<Vec<MlKemParameterSet>, Error> {
        Ok(self
            .module
            .resolve_token_uri(token)?
            .ml_kem_generation_options()?)
    }
}
impl ManagementSession<'_> {
    /// Generate a persistent ML-KEM pair in an RW session. The private key stays
    /// sensitive and nonextractable; no private value or seed is read or imported.
    /// Explicit ID/label selection follows the signing-key generation contract.
    pub fn generate_ml_kem_key_pair(
        &mut self,
        parameter: MlKemParameterSet,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        self.session
            .generate_ml_kem_key_pair(parameter, id, label)?;
        Ok(())
    }
    /// Read current parameters and validate the chosen direction's permissions,
    /// mechanism flags and entry point. Does not encapsulate or decapsulate.
    pub fn ml_kem_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: MlKemOperation,
    ) -> Result<MlKemCapabilities, Error> {
        Ok(self.session.ml_kem_capabilities(key, operation)?)
    }
    /// Return public ciphertext and retain the raw shared secret on the token under
    /// the request's ID/label. The new private generic secret permits only derivation;
    /// it is sensitive, nonextractable and 32 bytes long. Requires RW mode.
    /// Apply a protocol KDF and authenticate the peer before use. No retry or rollback;
    /// close this session before releasing ciphertext when checked cleanup is required.
    pub fn encapsulate_ml_kem(
        &mut self,
        key: &PublicKeyRef,
        request: &MlKemRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.encapsulate_ml_kem(key, request)?)
    }
    /// Retain a decapsulated raw secret with the same restrictions as encapsulation.
    /// Exact ciphertext length is checked before crypto. Same-length altered ciphertexts
    /// may succeed with a different secret through ML-KEM implicit rejection.
    /// No shared-secret bytes leave the token; no authentication is inferred.
    pub fn decapsulate_ml_kem(
        &mut self,
        key: &PrivateKeyRef,
        request: &MlKemRequest<'_>,
        ciphertext: &[u8],
    ) -> Result<(), Error> {
        Ok(self.session.decapsulate_ml_kem(key, request, ciphertext)?)
    }
}
