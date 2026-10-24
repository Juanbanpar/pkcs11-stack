// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{Action, ChoiceMenu, ManagementTask, Overlay};
use crate::{
    app::{App, Message},
    state::TokenPage,
};
use iced::Task;

impl App {
    pub(crate) fn update_ui(&mut self, action: Action) -> Task<Message> {
        let modal = self.state.presentation.choice.is_some()
            || self.state.presentation.overlay.is_some()
            || self.state.dialog.is_some()
            || self.state.login_form.is_some();
        match action {
            Action::Focus(id) => {
                self.state.presentation.focused = Some(id.clone().into());
                return super::focus::focus(id);
            }
            Action::RecordFocus => return super::focus::record(),
            Action::Focused(id) => self.state.presentation.focused = Some(id),
            Action::MoveIn(group, movement) => {
                use super::focus::Group;
                let ids = match group {
                    Group::Objects => super::sorted_objects(&self.state)
                        .iter()
                        .map(|entry| format!("object-{:?}", entry.id))
                        .collect(),
                    Group::Mechanisms => super::sorted_mechanisms(&self.state)
                        .iter()
                        .map(|entry| format!("mechanism-{:?}", entry.id))
                        .collect(),
                    Group::Pages => [
                        TokenPage::Overview,
                        TokenPage::Objects,
                        TokenPage::Mechanisms,
                        TokenPage::Operations,
                        TokenPage::Administration,
                    ]
                    .iter()
                    .map(|page| format!("page-{page:?}"))
                    .collect(),
                    Group::Choices => self
                        .state
                        .presentation
                        .choice
                        .as_ref()
                        .map(|choice| {
                            (0..choice.options.len())
                                .map(|index| {
                                    if index == 0 {
                                        "choice-first".into()
                                    } else if index + 1 == choice.options.len() {
                                        "choice-last".into()
                                    } else {
                                        format!("choice-{index}")
                                    }
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    Group::Navigation => {
                        let mut ids = vec!["screen-Welcome".into(), "screen-Modules".into()];
                        for module in &self.state.loaded_modules {
                            ids.push(format!("module-{:?}", module.id));
                            if !self.state.presentation.collapsed.contains(&module.id.0) {
                                ids.extend(
                                    module
                                        .tokens
                                        .iter()
                                        .map(|token| format!("token-{:?}", token.id)),
                                );
                            }
                        }
                        ids
                    }
                };
                return super::focus::walk(Some(ids), movement);
            }
            Action::Resize(size) => self.state.presentation.width = size.width,
            Action::SystemTheme(mode) => {
                self.state.presentation.system_dark = mode == iced::theme::Mode::Dark
            }
            Action::SetAppearance(appearance) => self.state.presentation.appearance = appearance,
            Action::Escape => {
                if self.state.presentation.choice.is_some()
                    || self.state.presentation.overlay.is_some()
                {
                    return self.update_ui(Action::Close);
                }
                if let Some(id) = self.state.login_form.as_ref().map(|form| form.id) {
                    return self.update(Message::DismissLogin(id));
                }
                if self.state.dialog.is_some() {
                    return self.update(Message::DismissDialog);
                }
                if self.state.can_submit() {
                    if let Some(id) = self.state.crypto_form.as_ref().map(|form| form.id) {
                        return self.update(Message::DismissCrypto(id));
                    }
                    if let Some(id) = self.state.cipher_form.as_ref().map(|form| form.id) {
                        return self.update(Message::DismissCipher(id));
                    }
                    if let Some(id) = self.state.key_form.as_ref().map(|form| form.id) {
                        return self.update(Message::DismissKeyOperation(id));
                    }
                    if let Some(id) = self.state.administration_form.as_ref().map(|form| form.id) {
                        return self.update(Message::DismissAdministration(id));
                    }
                    return self.update_ui(Action::Task(None));
                }
            }
            Action::Close => {
                self.state.presentation.choice = None;
                self.state.presentation.overlay = None;
                self.state.picker_request = None;
                if let Some(id) = self.state.presentation.restore_focus.take() {
                    return super::focus::focus(id);
                }
            }
            Action::Choose(message) => {
                let focus = self.update_ui(Action::Close);
                return Task::batch([self.update(*message), focus]);
            }
            Action::Choice { id, title, options } => {
                if self.state.can_submit() {
                    self.state.presentation.restore_focus = Some(id.into());
                    self.state.presentation.choice = Some(ChoiceMenu { title, options });
                    return super::focus::focus("choice-first");
                }
            }
            Action::AddModule | Action::Appearance | Action::KeyboardHelp if !modal => {
                if matches!(action, Action::AddModule) && !self.state.can_submit() {
                    return Task::none();
                }
                let (overlay, focus) = match action {
                    Action::AddModule => (Overlay::AddModule, "module-path"),
                    Action::Appearance => (Overlay::Appearance, "appearance-System"),
                    _ => (Overlay::KeyboardHelp, "overlay-close"),
                };
                self.state.presentation.restore_focus = self.state.presentation.focused.clone();
                self.state.presentation.overlay = Some(overlay);
                return super::focus::focus(focus);
            }
            Action::ToggleModule(id) if !modal => {
                if !self.state.presentation.collapsed.remove(&id.0) {
                    self.state.presentation.collapsed.insert(id.0);
                }
            }
            Action::BackToList if !modal => self.state.presentation.show_detail = false,
            Action::Task(task) if !modal && self.state.can_submit() => {
                self.state.presentation.task = task;
                // Switching task invalidates file pickers and abandons the old form.
                self.state.management = Default::default();
                self.state.random = Default::default();
                if task == Some(ManagementTask::Generate) {
                    return self.update(Message::ReadCapabilities);
                }
            }
            Action::SortObjects(sort) if !modal => {
                let ui = &mut self.state.presentation;
                ui.object_descending = ui.object_sort == sort && !ui.object_descending;
                ui.object_sort = sort;
            }
            Action::SortMechanisms(sort) if !modal => {
                let ui = &mut self.state.presentation;
                ui.mechanism_descending = ui.mechanism_sort == sort && !ui.mechanism_descending;
                ui.mechanism_sort = sort;
            }
            Action::Refresh if !modal => {
                let message = match self.state.token_page {
                    TokenPage::Objects if self.state.token().is_some() => Message::RefreshObjects,
                    TokenPage::Mechanisms if self.state.token().is_some() => {
                        Message::RefreshMechanisms
                    }
                    _ => Message::Refresh,
                };
                return self.update(message);
            }
            Action::Filter if !modal => {
                let id = match self.state.token_page {
                    TokenPage::Objects => "object-filter",
                    TokenPage::Mechanisms => "mechanism-filter",
                    _ => return Task::none(),
                };
                return super::focus::focus(id);
            }
            _ => {}
        }
        Task::none()
    }
}
