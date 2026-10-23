// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    app::Message,
    backend::ModuleEntry,
    state::{Dialog, Notification, Screen, UiState},
    views::{token, welcome},
};
use iced::{
    Element, Length,
    widget::{button, column, container, row, rule, scrollable, text, text_input},
};

pub fn module_form(state: &UiState) -> Element<'_, Message> {
    let enabled = state.can_submit();
    column![
        text("Module file"),
        row![
            text_input("/path/to/PKCS#11 module", &state.module_path)
                .on_input_maybe(enabled.then_some(Message::EditPath))
                .on_submit_maybe(
                    (enabled && !state.module_path.is_empty()).then_some(Message::Load)
                ),
            button("Browse…").on_press_maybe(
                (enabled && state.picker_request.is_none()).then_some(Message::Browse)
            ),
            button("Load").on_press_maybe(
                (enabled && !state.module_path.is_empty()).then_some(Message::Load)
            ),
        ]
        .spacing(10),
        text("Loading executes the selected library. Use a module from a trusted provider.")
            .size(14),
    ]
    .spacing(8)
    .into()
}
pub(super) fn field<'a>(label: &'a str, value: impl Into<String>) -> Element<'a, Message> {
    row![
        text(label).width(180),
        text(value.into()).width(Length::Fill)
    ]
    .spacing(12)
    .into()
}
fn module_view(module: &ModuleEntry) -> Element<'_, Message> {
    let mut overview = column![
        text(module.label()).size(30),
        field("Path", module.path.to_string_lossy().into_owned()),
        field("Description", &module.description),
        field("Manufacturer", &module.manufacturer),
        field("Library version", &module.library_version),
        field("PKCS#11 version", &module.cryptoki_version),
        text(format!(
            "{} slots · {} tokens",
            module.slots.len(),
            module.tokens.len()
        ))
        .size(20),
    ]
    .spacing(12);
    if let Some(error) = module.discovery_error {
        overview = overview
            .push(text(error.message()))
            .push(text("Refresh to retry discovery, or unload the module."));
    } else if module.slots.is_empty() {
        overview = overview.push(text("The module reports no slots."));
    }
    for slot in &module.slots {
        overview = overview.push(
            container(
                column![
                    text(format!("Slot {} · {}", slot.id, slot.description)),
                    text(format!(
                        "{} · {}",
                        slot.manufacturer,
                        if slot.token_present {
                            "token present"
                        } else {
                            "no token present"
                        }
                    )),
                ]
                .spacing(6),
            )
            .padding(12)
            .style(container::rounded_box),
        );
    }
    if module.tokens.is_empty() && module.discovery_error.is_none() {
        overview = overview.push(text("No tokens available. Insert a token and refresh."));
    }
    overview.into()
}

pub fn view(state: &UiState) -> Element<'_, Message> {
    let selected = state.module().is_some() && state.can_submit();
    let toolbar = row![
        text("PKCS#11 Desktop").size(22).width(Length::Fill),
        button("Refresh module").on_press_maybe(selected.then_some(Message::Refresh)),
        button("Unload").on_press_maybe(selected.then_some(Message::Unload)),
        button(if state.dark_theme {
            "Light theme"
        } else {
            "Dark theme"
        })
        .on_press(Message::ToggleTheme),
        button("About").on_press(Message::About),
        button("Quit").on_press(Message::CloseRequested),
    ]
    .spacing(10)
    .align_y(iced::Alignment::Center);
    let mut navigation = column![
        button("Welcome")
            .width(Length::Fill)
            .on_press(Message::Navigate(Screen::Welcome)),
        button("Modules")
            .width(Length::Fill)
            .on_press(Message::Navigate(Screen::Modules)),
    ]
    .spacing(10);
    if state.loaded_modules.is_empty() {
        navigation = navigation.push(text("No modules loaded").size(14));
    }
    for module in &state.loaded_modules {
        navigation = navigation.push(
            button(text(module.label()))
                .width(Length::Fill)
                .style(if state.selected_module == Some(module.id) {
                    button::primary
                } else {
                    button::secondary
                })
                .on_press(Message::SelectModule(module.id)),
        );
        for token in &module.tokens {
            let label = if token.label.is_empty() {
                "Unnamed token"
            } else {
                &token.label
            };
            navigation = navigation.push(
                container(
                    button(text(if token.serial.is_empty() {
                        label.to_owned()
                    } else {
                        format!("{label} · {}", token.serial)
                    }))
                    .width(Length::Fill)
                    .style(if state.selected_token == Some(token.id) {
                        button::primary
                    } else {
                        button::secondary
                    })
                    .on_press(Message::SelectToken {
                        module: module.id,
                        token: token.id,
                    }),
                )
                .padding([0, 12]),
            );
        }
    }
    let content = match state.screen {
        Screen::Welcome => welcome::view(state),
        Screen::Modules => {
            let mut detail = column![module_form(state)].spacing(24);
            if let Some(token) = state.token() {
                detail = detail.push(token::view(state, token));
            } else if let Some(module) = state.module() {
                detail = detail.push(module_view(module));
            } else {
                detail = detail
                    .push(text("Modules").size(30))
                    .push(text("Load a module or select one from the sidebar."));
            }
            detail.into()
        }
    };
    let mut detail = column![content].spacing(16);
    if let Some(notification) = state.notification {
        let message = match notification {
            Notification::RandomSaved(length) => text(format!(
                "{length} token random bytes saved to the requested file."
            )),
            _ => text(notification.text()),
        };
        detail = detail.push(
            container(
                row![
                    message.width(Length::Fill),
                    button("Dismiss").on_press(Message::DismissNotification)
                ]
                .spacing(12),
            )
            .width(Length::Fill)
            .padding(16)
            .style(container::rounded_box),
        );
    }
    if state.dialog == Some(Dialog::About) {
        detail = detail.push(
            container(
                column![
                    text("About PKCS#11 Desktop").size(20),
                    text("Native desktop application using Iced and pkcs11-client."),
                    button("Close").on_press(Message::DismissDialog),
                ]
                .spacing(12),
            )
            .padding(20)
            .style(container::rounded_box),
        );
    }
    let body = row![
        container(scrollable(navigation).spacing(8))
            .width(240)
            .height(Length::Fill)
            .padding(18)
            .style(container::rounded_box),
        container(scrollable(detail).spacing(8))
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(24),
    ]
    .spacing(12)
    .height(Length::Fill);
    let status = row![
        text(state.status()).size(14).width(Length::Fill),
        button("Cancel result").on_press_maybe(state.can_cancel().then_some(Message::Cancel))
    ]
    .spacing(10);
    container(
        column![
            toolbar,
            rule::horizontal(1),
            body,
            rule::horizontal(1),
            status
        ]
        .spacing(14),
    )
    .padding(18)
    .height(Length::Fill)
    .width(Length::Fill)
    .into()
}
