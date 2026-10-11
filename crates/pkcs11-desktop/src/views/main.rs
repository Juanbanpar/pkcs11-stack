// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    app::Message,
    state::{Dialog, Screen, UiState},
    views::welcome,
};
use iced::{
    Element, Length,
    widget::{button, column, container, row, rule, scrollable, text},
};

pub fn view(state: &UiState) -> Element<'_, Message> {
    let toolbar = row![
        text("PKCS#11 Desktop").size(22).width(Length::Fill),
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
        text("Navigation").size(18),
        button("Welcome")
            .width(Length::Fill)
            .on_press(Message::Navigate(Screen::Welcome)),
        button("Modules")
            .width(Length::Fill)
            .on_press(Message::Navigate(Screen::Modules)),
        text("No modules loaded").size(14),
    ]
    .spacing(12);
    for module in &state.loaded_modules {
        navigation = navigation.push(text(format!("{} · #{}", module.label, module.id.0)));
    }
    let content = match state.screen {
        Screen::Welcome => welcome::view(state),
        Screen::Modules => column![
            text("Modules").size(30),
            text("No modules loaded"),
            text("Module selection and token browsing will be available in the next milestone."),
        ]
        .spacing(18)
        .into(),
    };
    let mut detail = column![content].spacing(16);
    // Selection identifiers are desktop IDs; no session or raw handle is displayed.
    for (label, selection) in [
        ("Module", state.selected_module),
        ("Token", state.selected_token),
        ("Object", state.selected_object),
    ] {
        if let Some(id) = selection {
            detail = detail.push(text(format!("{label} #{}", id.0)));
        }
    }
    if let Some(notification) = state.notification {
        detail = detail.push(
            container(
                row![
                    text(notification.text()).width(Length::Fill),
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
                    text("PKCS#11 Desktop"),
                    button("Close").on_press(Message::DismissDialog),
                ]
                .spacing(12),
            )
            .padding(20)
            .style(container::rounded_box),
        );
    }
    let body = row![
        container(scrollable(navigation))
            .width(220)
            .height(Length::Fill)
            .padding(18)
            .style(container::rounded_box),
        container(scrollable(detail))
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(24),
    ]
    .spacing(12)
    .height(Length::Fill);

    container(
        column![
            toolbar,
            rule::horizontal(1),
            body,
            rule::horizontal(1),
            text(state.status()).size(14)
        ]
        .spacing(14),
    )
    .padding(18)
    .height(Length::Fill)
    .width(Length::Fill)
    .into()
}
