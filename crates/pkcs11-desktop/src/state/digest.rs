// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{
    BackendCommand, BackendError, Notification, OperationKind, PathBuf, RequestId, ResourceId,
    TokenPage, UiState,
};
use pkcs11_client::HashAlgorithm;

#[derive(Default)]
pub struct DigestUi {
    pub algorithms: Vec<HashAlgorithm>,
    pub algorithm: Option<HashAlgorithm>,
    pub loaded: bool,
    pub path: String,
    pub result: Option<String>,
    picked: Option<PathBuf>,
    pub picker: Option<(RequestId, ResourceId, ResourceId)>,
}
impl UiState {
    fn digest_target(&self) -> bool {
        self.can_submit()
            && self.token_page == TokenPage::Operations
            && self.presentation.task == Some(crate::ui::ManagementTask::Digest)
            && self
                .token()
                .is_some_and(|token| token.initialized && token.uri.is_some())
    }
    pub fn can_digest(&self) -> bool {
        self.digest_target()
            && self.digest.loaded
            && self
                .digest
                .algorithm
                .is_some_and(|a| self.digest.algorithms.contains(&a))
    }
    pub fn read_digest_algorithms(&mut self) -> Option<BackendCommand> {
        if !self.digest_target() {
            return None;
        }
        let module = self.module()?.id;
        let token = self.token()?.id;
        let id = self.begin(OperationKind::DigestOptions)?;
        self.digest.loaded = false;
        Some(BackendCommand::DigestOptions { id, module, token })
    }
    pub fn digest_algorithm(&mut self, algorithm: HashAlgorithm) {
        if self.digest_target() && self.digest.algorithms.contains(&algorithm) {
            self.digest.algorithm = Some(algorithm);
            self.digest.result = None;
        }
    }
    pub fn digest_path(&mut self, path: String) {
        if !self.digest_target() {
            return;
        }
        self.digest.path = path;
        self.digest.picked = None;
        self.digest.picker = None;
        self.digest.result = None;
    }
    pub fn digest_picker(&mut self) -> Option<RequestId> {
        if !self.digest_target() || self.digest.picker.is_some() {
            return None;
        }
        let module = self.module()?.id;
        let token = self.token()?.id;
        let id = self.request_id()?;
        self.digest.picker = Some((id, module, token));
        Some(id)
    }
    pub fn digest_picked(&mut self, id: RequestId, path: Option<PathBuf>) {
        let Some((request, module, token)) = self.digest.picker else {
            return;
        };
        if request != id {
            return;
        }
        self.digest.picker = None;
        if !self.digest_target()
            || self.selected_module != Some(module)
            || self.selected_token != Some(token)
        {
            return;
        }
        if let Some(path) = path {
            self.digest.path = path.to_string_lossy().into_owned();
            self.digest.picked = Some(path);
            self.digest.result = None;
        }
    }
    pub fn digest_file(&mut self) -> Option<BackendCommand> {
        if !self.can_digest() {
            return None;
        }
        if self.digest.path.is_empty() {
            self.notification = Some(Notification::Error(BackendError::CryptoRead));
            return None;
        }
        let module = self.module()?.id;
        let token = self.token()?.id;
        let algorithm = self.digest.algorithm?;
        let path = self
            .digest
            .picked
            .clone()
            .unwrap_or_else(|| self.digest.path.clone().into());
        let id = self.begin(OperationKind::Digest)?;
        self.digest.result = None;
        Some(BackendCommand::DigestFile {
            id,
            module,
            token,
            algorithm,
            path,
        })
    }
}
