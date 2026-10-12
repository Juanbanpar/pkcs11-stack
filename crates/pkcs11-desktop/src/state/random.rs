// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use pkcs11_client::RandomRequest;

pub struct RandomUi {
    pub length: String,
    pub path: String,
    picked: Option<PathBuf>,
    pub picker: Option<(RequestId, ResourceId, ResourceId)>,
}
impl Default for RandomUi {
    fn default() -> Self {
        Self {
            length: "32".into(),
            path: String::new(),
            picked: None,
            picker: None,
        }
    }
}
#[derive(Clone, Copy)]
pub enum RandomField {
    Length,
    Path,
}
impl UiState {
    pub fn can_random(&self) -> bool {
        self.can_submit()
            && self.token_page == TokenPage::Operations
            && self.token().is_some_and(TokenEntry::can_random)
    }
    pub fn random_edit(&mut self, field: RandomField, value: String) {
        if !self.can_submit() || self.token_page != TokenPage::Operations {
            return;
        }
        match field {
            RandomField::Length => self.random.length = value,
            RandomField::Path => {
                self.random.path = value;
                self.random.picked = None;
                self.random.picker = None;
            }
        }
    }
    pub fn random_picker(&mut self) -> Option<RequestId> {
        if !self.can_random() || self.random.picker.is_some() {
            return None;
        }
        let module = self.module()?.id;
        let token = self.token()?.id;
        let id = self.request_id()?;
        self.random.picker = Some((id, module, token));
        Some(id)
    }
    pub fn random_picked(&mut self, id: RequestId, path: Option<PathBuf>) {
        let Some((request, module, token)) = self.random.picker else {
            return;
        };
        if request != id {
            return;
        }
        self.random.picker = None;
        if !self.can_random()
            || self.selected_module != Some(module)
            || self.selected_token != Some(token)
        {
            return;
        }
        if let Some(path) = path {
            self.random.path = path.to_string_lossy().into_owned();
            self.random.picked = Some(path);
        }
    }
    pub fn generate_random(&mut self) -> Option<BackendCommand> {
        if !self.can_random() {
            return None;
        }
        let request = self
            .random
            .length
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|length| RandomRequest::new(length).ok());
        if self.random.path.is_empty() || request.is_none() {
            self.notification = Some(Notification::Error(BackendError::RandomLength));
            return None;
        }
        let module = self.module()?.id;
        let token = self.token()?.id;
        let path = self
            .random
            .picked
            .clone()
            .unwrap_or_else(|| PathBuf::from(&self.random.path));
        let id = self.begin(OperationKind::Random)?;
        self.random = RandomUi::default();
        Some(BackendCommand::Random {
            id,
            module,
            token,
            request: request.unwrap(),
            path,
        })
    }
}
