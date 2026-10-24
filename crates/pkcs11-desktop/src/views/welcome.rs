// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    app::Message,
    state::UiState,
    ui::{
        Action, button,
        components::{EMPHASIS, muted},
        theme,
    },
};
use iced::{
    Element, Length,
    widget::{column, container, row, text},
};
use iced_fonts::lucide;

pub fn view(state: &UiState) -> Element<'_, Message> {
    let mut content = column![
        container(column![
            row![lucide::shield().size(32).style(theme::accent), column![muted("PKCS#11 WORKSPACE").size(11).font(EMPHASIS), text("Connect a provider module").size(28).font(EMPHASIS)].spacing(6)].spacing(16).align_y(iced::Alignment::Center),
            text("Browse tokens, manage keys and certificates, and run cryptographic operations through a trusted PKCS#11 provider.").size(16),
            button(row![lucide::plus().size(17), text("Add Module…")].spacing(8)).id("welcome-add-module").style(button::primary).on_press_maybe(state.can_submit().then_some(Message::Ui(Action::AddModule))),
            muted("Loading a module executes its library. Choose a file from a trusted provider.").size(13),
        ].spacing(18)).padding(24).width(Length::Fill).style(theme::surface),
    ].spacing(24).max_width(780);
    if let Some(module) = state.loaded_modules.first() {
        content = content.push(
            column![
                text("Continue browsing").size(18).font(EMPHASIS),
                muted(format!(
                    "Modules already loaded in this window: {}",
                    state.loaded_modules.len()
                )),
                button("Open loaded modules")
                    .id("welcome-continue")
                    .on_press(Message::SelectModule(module.id))
            ]
            .spacing(10),
        );
    } else {
        content = content.push(column![
            text("Start with your token").size(18).font(EMPHASIS),
            row![lucide::cpu().size(18).style(theme::accent), column![text("Load the provider").size(14).font(EMPHASIS), muted("Choose the library supplied by your token vendor.")].spacing(4)].spacing(12),
            row![lucide::key().size(18).style(theme::accent), column![text("Select a token").size(14).font(EMPHASIS), muted("Check its identity, then log in when an action requires it.")].spacing(4)].spacing(12),
            row![lucide::file_check().size(18).style(theme::accent), column![text("Inspect and act").size(14).font(EMPHASIS), muted("Browse objects or choose a token operation. Changes require an explicit action.")].spacing(4)].spacing(12),
        ].spacing(14));
    }
    content.into()
}
