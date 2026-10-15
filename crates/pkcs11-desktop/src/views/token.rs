// SPDX-License-Identifier: MIT OR Apache-2.0
use super::main::field;
use crate::{
    app::Message,
    backend::{CryptoMode, LoginRole, LoginState, MetadataField, TokenEntry},
    state::{Dialog, TokenPage, UiState},
};
use iced::{
    Element, Length,
    widget::{button, checkbox, column, container, row, rule, scrollable, text, text_input},
};
use secrecy::ExposeSecret;

pub fn view<'a>(state: &'a UiState, token: &'a TokenEntry) -> Element<'a, Message> {
    let mut tabs = row![].spacing(10);
    for (label, page) in [
        ("Overview", TokenPage::Overview),
        ("Objects", TokenPage::Objects),
        ("Mechanisms", TokenPage::Mechanisms),
        ("Operations", TokenPage::Operations),
        ("Administration", TokenPage::Administration),
    ] {
        tabs = tabs.push(
            button(label)
                .style(if state.token_page == page {
                    button::primary
                } else {
                    button::secondary
                })
                .on_press_maybe(state.can_submit().then_some(Message::ShowPage(page))),
        );
    }
    let content = match state.token_page {
        TokenPage::Overview => overview(token),
        TokenPage::Objects => objects(state),
        TokenPage::Mechanisms => mechanisms(state),
        TokenPage::Operations => super::operations::view(state),
        TokenPage::Administration => super::administration::view(state),
    };
    column![
        text(if token.label.is_empty() {
            "Unnamed token"
        } else {
            &token.label
        })
        .size(30),
        authentication(state, token),
        tabs,
        content
    ]
    .spacing(18)
    .into()
}
fn authentication<'a>(state: &'a UiState, token: &'a TokenEntry) -> Element<'a, Message> {
    let enabled = state.can_submit();
    let mut content = column![
        row![
            text(token.login.label()).width(Length::Fill),
            button("USER login").on_press_maybe(
                (enabled && token.can_login(LoginRole::User))
                    .then_some(Message::OpenLogin(LoginRole::User))
            ),
            button("SO login").on_press_maybe(
                (enabled && token.can_login(LoginRole::SecurityOfficer))
                    .then_some(Message::OpenLogin(LoginRole::SecurityOfficer))
            ),
            button("Logout").on_press_maybe(
                (enabled && token.login != LoginState::Public).then_some(Message::Logout)
            ),
        ]
        .spacing(10)
    ]
    .spacing(12);
    if let Some(form) = &state.login_form {
        let id = form.id;
        content = content.push(
            text(match form.role {
                LoginRole::User => "Login as USER",
                LoginRole::SecurityOfficer => "Login as Security Officer",
            })
            .size(20),
        );
        if token.protected_path {
            content = content.push(
                checkbox(form.protected_path)
                    .label("Use token's protected authentication path")
                    .on_toggle(move |enabled| Message::ProtectedPath { id, enabled }),
            );
        }
        if form.protected_path {
            content = content.push(text("Complete authentication on the token when prompted."));
        } else {
            content = content.push(
                text_input("PIN", form.pin.expose_secret())
                    .secure(true)
                    .on_input(move |pin| Message::PinInput {
                        id,
                        pin: pin.into(),
                    })
                    .on_submit(Message::SubmitLogin(id)),
            );
        }
        content = content
            .push(
                text("Each submission makes one login attempt. Failed attempts can lock the PIN.")
                    .size(14),
            )
            .push(
                row![
                    button("Login").on_press(Message::SubmitLogin(id)),
                    button("Cancel").on_press(Message::DismissLogin(id))
                ]
                .spacing(10),
            );
    }
    container(content)
        .padding(12)
        .style(container::rounded_box)
        .into()
}
fn overview(token: &TokenEntry) -> Element<'_, Message> {
    let mut content = column![
        field("Manufacturer", &token.manufacturer),
        field("Model", &token.model),
        field("Serial", &token.serial),
        field("Current slot", token.slot_id.to_string())
    ]
    .spacing(12);
    for (label, value) in &token.details {
        content = content.push(field(label, value));
    }
    content
        .push(text("Token locator").size(20))
        .push(text(token.uri.as_deref().unwrap_or(
            "The reported token metadata cannot form a supported locator.",
        )))
        .into()
}
fn metadata(fields: &[MetadataField]) -> Element<'_, Message> {
    let mut content = column![].spacing(10);
    for entry in fields {
        let value = entry
            .value
            .as_deref()
            .map(|value| if value.is_empty() { "(empty)" } else { value })
            .unwrap_or(entry.status);
        content = content.push(field(entry.name, value));
    }
    content.into()
}
fn objects(state: &UiState) -> Element<'_, Message> {
    let enabled = state.can_submit();
    let mut list = column![].spacing(8);
    let mut count = 0;
    for object in state
        .objects
        .iter()
        .filter(|entry| entry.matches(&state.object_filter))
    {
        count += 1;
        let label = if object.label.is_empty() {
            "Unnamed object"
        } else {
            &object.label
        };
        list = list.push(
            button(
                column![
                    text(label),
                    text(format!(
                        "{} · ID {}",
                        object.class_name(),
                        if object.identifier.is_empty() {
                            "—"
                        } else {
                            &object.identifier
                        }
                    ))
                    .size(13)
                ]
                .spacing(4),
            )
            .width(Length::Fill)
            .style(if state.selected_object == Some(object.id) {
                button::primary
            } else {
                button::secondary
            })
            .on_press_maybe(enabled.then_some(Message::SelectObject(object.id))),
        );
    }
    if count == 0 {
        list = list.push(text(if !state.objects_loaded {
            "Object list has not been read. Refresh to retry."
        } else if state.objects.is_empty() {
            "No persistent objects are visible in the current authentication state."
        } else {
            "No objects match the filter."
        }));
    }
    let mut detail = column![].spacing(12);
    if let Some(object) = state.object() {
        detail = detail
            .push(text("Object metadata").size(20))
            .push(metadata(&object.fields));
        if let Some(uri) = &object.uri {
            detail = detail.push(text("Object locator").size(18)).push(text(uri));
        } else {
            detail = detail.push(text(
                "The available identity attributes cannot form a supported object locator.",
            ));
        }
        detail = detail.push(
            row![
                button("Export public object…")
                    .on_press_maybe(state.can_export().then_some(Message::ExportObject)),
                button("Delete object…").on_press_maybe(
                    (state.can_manage() && !object.ambiguous && object.uri.is_some())
                        .then_some(Message::RequestDelete)
                )
            ]
            .spacing(10),
        );
        match object.class {
            Some(pkcs11_client::ObjectClass::PRIVATE_KEY) => {
                detail = detail.push(
                    button("Derive ECDH secret…").on_press_maybe(
                        state
                            .can_open_key_operation(CryptoMode::Derive)
                            .then_some(Message::OpenKeyOperation(CryptoMode::Derive)),
                    ),
                );
                detail = detail.push(
                    button("Decrypt RSA OAEP…").on_press_maybe(
                        state
                            .can_open_cipher(CryptoMode::Decrypt)
                            .then_some(Message::OpenCipher(CryptoMode::Decrypt)),
                    ),
                );
                detail = detail.push(
                    button("Sign file…").on_press_maybe(
                        state
                            .can_open_crypto(CryptoMode::Sign)
                            .then_some(Message::OpenCrypto(CryptoMode::Sign)),
                    ),
                );
            }
            Some(pkcs11_client::ObjectClass::CERTIFICATE) => {
                detail = detail.push(
                    button("Verify signature…").on_press_maybe(
                        state
                            .can_open_crypto(CryptoMode::Verify)
                            .then_some(Message::OpenCrypto(CryptoMode::Verify)),
                    ),
                );
            }
            Some(pkcs11_client::ObjectClass::PUBLIC_KEY) => {
                detail = detail.push(
                    button("Encrypt RSA OAEP…").on_press_maybe(
                        state
                            .can_open_cipher(CryptoMode::Encrypt)
                            .then_some(Message::OpenCipher(CryptoMode::Encrypt)),
                    ),
                );
            }
            Some(pkcs11_client::ObjectClass::SECRET_KEY) => {
                detail = detail.push(
                    row![
                        button("Wrap AES key…").on_press_maybe(
                            state
                                .can_open_key_operation(CryptoMode::Wrap)
                                .then_some(Message::OpenKeyOperation(CryptoMode::Wrap))
                        ),
                        button("Unwrap AES key…").on_press_maybe(
                            state
                                .can_open_key_operation(CryptoMode::Unwrap)
                                .then_some(Message::OpenKeyOperation(CryptoMode::Unwrap))
                        )
                    ]
                    .spacing(10),
                );
            }
            _ => {}
        }
        if let Some(Dialog::Delete(id)) = state.dialog {
            detail = detail.push(container(column![
                text("Delete selected object?").size(20),
                text("This permanently deletes this object only; related keys and certificates are kept."),
                text(object.uri.as_deref().unwrap_or("")),
                row![button("Delete permanently").on_press(Message::ConfirmDelete(id)), button("Cancel").on_press(Message::DismissDialog)].spacing(10),
            ].spacing(10)).padding(12).style(container::rounded_box));
        }
        if object.ambiguous {
            detail = detail.push(text(
                "Several listed objects share this locator; details cannot be selected uniquely.",
            ));
        } else if let Some(fields) = &state.object_details {
            detail = detail.push(rule::horizontal(1)).push(metadata(fields));
        } else if object.uri.is_some() {
            detail = detail.push(text(
                "Details are read on selection. Select again to retry a failed or cancelled read.",
            ));
        }
        if state.crypto_form.is_some() {
            detail = detail.push(super::crypto::view(state));
        }
        if state.key_form.is_some() {
            detail = detail.push(super::key_operations::view(state));
        }
        if state.cipher_form.is_some() {
            detail = detail.push(super::cipher::view(state));
        }
    } else {
        detail = detail.push(text("Select an object to read its metadata."));
    }
    column![
        row![
            text_input("Filter label, class, ID or locator", &state.object_filter)
                .on_input(Message::ObjectFilter),
            button("Refresh objects").on_press_maybe(enabled.then_some(Message::RefreshObjects))
        ]
        .spacing(10),
        text(format!(
            "{count} of {} objects · persistent objects visible to this role",
            state.objects.len()
        ))
        .size(14),
        row![
            container(scrollable(list).height(340)).width(Length::FillPortion(2)),
            container(detail).width(Length::FillPortion(3)).padding(12)
        ]
        .spacing(16)
    ]
    .spacing(14)
    .into()
}
fn mechanisms(state: &UiState) -> Element<'_, Message> {
    let mut list = column![].spacing(8);
    let mut count = 0;
    for entry in state
        .mechanisms
        .iter()
        .filter(|entry| entry.matches(&state.mechanism_filter))
    {
        count += 1;
        list = list.push(
            button(column![text(&entry.name), text(&entry.identifier).size(13)])
                .width(Length::Fill)
                .style(if state.selected_mechanism == Some(entry.id) {
                    button::primary
                } else {
                    button::secondary
                })
                .on_press(Message::SelectMechanism(entry.id)),
        );
    }
    if count == 0 {
        list = list.push(text(if !state.mechanisms_loaded {
            "Mechanism list has not been read. Refresh to retry."
        } else if state.mechanisms.is_empty() {
            "The token advertises no mechanisms."
        } else {
            "No mechanisms match the filter."
        }));
    }
    let mut detail = column![].spacing(12);
    if let Some(entry) = state
        .mechanisms
        .iter()
        .find(|entry| Some(entry.id) == state.selected_mechanism)
    {
        detail = detail
            .push(text(&entry.name).size(20))
            .push(field("Identifier", &entry.identifier))
            .push(field("Minimum key size", entry.minimum.to_string()))
            .push(field("Maximum key size", entry.maximum.to_string()))
            .push(
                text("Bounds are provider values; units and meaning depend on the mechanism.")
                    .size(14),
            )
            .push(text("Advertised flags").size(18));
        if entry.flags.is_empty() {
            detail = detail.push(text("No flags reported."));
        }
        for flag in &entry.flags {
            detail = detail.push(text(*flag));
        }
    } else {
        detail = detail.push(text("Select a mechanism for provider flags and bounds."));
    }
    column![
        row![
            text_input("Filter name, identifier or flag", &state.mechanism_filter)
                .on_input(Message::MechanismFilter),
            button("Refresh mechanisms")
                .on_press_maybe(state.can_submit().then_some(Message::RefreshMechanisms))
        ]
        .spacing(10),
        text(format!("{count} of {} mechanisms", state.mechanisms.len())).size(14),
        row![
            container(scrollable(list).height(340)).width(Length::FillPortion(2)),
            container(detail).width(Length::FillPortion(3)).padding(12)
        ]
        .spacing(16)
    ]
    .spacing(14)
    .into()
}
