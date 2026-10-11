// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{app::Message, state::UiState, views::main::module_form};
use iced::{
    Element,
    widget::{column, text},
};

pub fn view(state: &UiState) -> Element<'_, Message> {
    column![
        text("Welcome").size(30),
        text("Browse PKCS#11 modules and tokens.").size(20),
        text("Choose a module file, then load it to inspect its library, slots and tokens."),
        module_form(state),
    ]
    .spacing(18)
    .into()
}
