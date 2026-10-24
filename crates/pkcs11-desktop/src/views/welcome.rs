// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    app::Message,
    state::UiState,
    ui::{Action, button},
};
use iced::{
    Element,
    widget::{column, text},
};

pub fn view(state: &UiState) -> Element<'_, Message> {
    column![
        text("Welcome").size(30),
        text("Browse PKCS#11 tokens and manage their objects.").size(20),
        text("Add a trusted provider module to inspect tokens, authenticate and perform cryptographic operations. Loading a module executes its library."),
        button("Add Module…").id("welcome-add-module").style(button::primary)
            .on_press_maybe(state.can_submit().then_some(Message::Ui(Action::AddModule))),
    ].spacing(18).max_width(680).into()
}
