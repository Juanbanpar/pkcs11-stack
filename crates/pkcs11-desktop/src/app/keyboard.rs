// SPDX-License-Identifier: MIT OR Apache-2.0
use super::Message;

pub(crate) fn shortcut(
    key: &iced::keyboard::Key,
    modifiers: iced::keyboard::Modifiers,
) -> Option<Message> {
    use crate::ui::Action;
    use iced::keyboard::{Key, key::Named};
    if key == &Key::Named(Named::Escape) {
        return Some(Message::Ui(Action::Escape));
    }
    if !modifiers.command() || modifiers.alt() || modifiers.shift() {
        return None;
    }
    match key.as_ref() {
        Key::Character("o") => Some(Message::Ui(Action::AddModule)),
        Key::Character("f") => Some(Message::Ui(Action::Filter)),
        Key::Character("r") => Some(Message::Ui(Action::Refresh)),
        Key::Character("q") => Some(Message::CloseRequested),
        _ => None,
    }
}

pub(crate) fn focus_navigation(
    key: iced::keyboard::Key,
    modifiers: iced::keyboard::Modifiers,
) -> Option<Message> {
    use iced::keyboard::{Key, key::Named};
    if key == Key::Named(Named::Tab)
        && !modifiers.control()
        && !modifiers.alt()
        && !modifiers.logo()
    {
        Some(Message::MoveFocus {
            backwards: modifiers.shift(),
        })
    } else {
        None
    }
}
