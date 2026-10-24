// SPDX-License-Identifier: MIT OR Apache-2.0
use super::main::field;
use crate::ui::{button, checkbox, text_input};
use crate::{
    app::Message,
    backend::{CryptoMode, LoginRole, LoginState, MetadataField, TokenEntry},
    state::{TokenPage, UiState},
};
use iced::{
    Element, Length,
    widget::{column, container, row, rule, scrollable, text},
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
                .arrows()
                .style(if state.token_page == page {
                    crate::ui::theme::selected
                } else {
                    crate::ui::theme::navigation
                })
                .on_press_maybe(state.can_submit().then_some(Message::ShowPage(page))),
        );
    }
    let content: Element<'_, Message> = match state.token_page {
        TokenPage::Overview => scrollable(overview(token)).spacing(8).into(),
        TokenPage::Objects => objects(state),
        TokenPage::Mechanisms => mechanisms(state),
        TokenPage::Operations => scrollable(super::operations::view(state)).spacing(8).into(),
        TokenPage::Administration => scrollable(super::administration::view(state))
            .spacing(8)
            .into(),
    };
    column![
        text(if token.label.is_empty() {
            "Unnamed token"
        } else {
            &token.label
        })
        .size(30),
        authentication(state, token),
        tabs.wrap(),
        content
    ]
    .spacing(16)
    .height(Length::Fill)
    .into()
}
fn authentication<'a>(state: &'a UiState, token: &'a TokenEntry) -> Element<'a, Message> {
    let enabled = state.can_submit();
    let content = column![
        row![
            iced_aw::Badge::new(text(token.login.label()).size(14))
                .padding(6)
                .style(|theme: &iced::Theme, _| {
                    let pair = theme.extended_palette().background.strong;
                    iced_aw::style::badge::Style {
                        background: pair.color.into(),
                        text_color: pair.text,
                        border_radius: Some(12.0),
                        border_width: 0.0,
                        border_color: None,
                    }
                }),
            iced::widget::space().width(Length::Fill),
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
        .align_y(iced::Alignment::Center)
    ]
    .spacing(12);

    container(content)
        .padding(12)
        .style(crate::ui::theme::surface)
        .into()
}
pub(super) fn login<'a>(state: &'a UiState, token: &'a TokenEntry) -> Element<'a, Message> {
    let mut content = column![].spacing(12);
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
                    button("Login")
                        .style(button::primary)
                        .on_press(Message::SubmitLogin(id)),
                    button("Cancel")
                        .id("modal-cancel")
                        .on_press(Message::DismissLogin(id))
                ]
                .spacing(10),
            );
    }
    content.into()
}

fn overview(token: &TokenEntry) -> Element<'_, Message> {
    let identity = column![
        field("Manufacturer", &token.manufacturer),
        field("Model", &token.model),
        field("Serial", &token.serial),
        field("Current slot", token.slot_id.to_string())
    ]
    .spacing(12);
    let mut capabilities = column![].spacing(12);
    for (label, value) in &token.details {
        capabilities = capabilities.push(field(label, value));
    }
    column![
        text("Identity").size(20),
        container(identity)
            .padding(16)
            .width(Length::Fill)
            .style(crate::ui::theme::surface),
        text("Capabilities and PIN limits").size(20),
        container(capabilities)
            .padding(16)
            .width(Length::Fill)
            .style(crate::ui::theme::surface),
        text("Token locator").size(20),
        text(
            token
                .uri
                .as_deref()
                .unwrap_or("The reported token metadata cannot form a supported locator.")
        )
        .font(iced::Font::MONOSPACE),
    ]
    .spacing(12)
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
        content = content.push(
            column![
                text(entry.name).size(14),
                text(value).wrapping(text::Wrapping::WordOrGlyph)
            ]
            .spacing(4),
        );
    }
    content.into()
}
fn objects(state: &UiState) -> Element<'_, Message> {
    let task = if let Some(form) = &state.crypto_form {
        Some((super::crypto::view(state), Message::DismissCrypto(form.id)))
    } else if let Some(form) = &state.cipher_form {
        Some((super::cipher::view(state), Message::DismissCipher(form.id)))
    } else {
        state.key_form.as_ref().map(|form| {
            (
                super::key_operations::view(state),
                Message::DismissKeyOperation(form.id),
            )
        })
    };
    if let Some((task, back)) = task {
        let mut context = column![
            button("Back to Objects")
                .id("object-task-back")
                .on_press(back)
        ]
        .spacing(12);
        if let Some(object) = state.object() {
            context = context.push(
                text(if object.label.is_empty() {
                    "Unnamed object"
                } else {
                    &object.label
                })
                .size(20),
            );
            if let Some(uri) = &object.uri {
                context = context.push(
                    text(uri)
                        .size(14)
                        .font(iced::Font::MONOSPACE)
                        .wrapping(text::Wrapping::Glyph),
                );
            }
        }
        return scrollable(context.push(task).max_width(800))
            .spacing(8)
            .into();
    }
    let enabled = state.can_submit();
    let entries = crate::ui::sorted_objects(state);
    let count = entries.len();
    let columns = [
        iced::widget::table::column(
            sort_object(state, "Label", crate::ui::ObjectSort::Label),
            move |object: &crate::backend::ObjectEntry| -> Element<'_, Message> {
                button(
                    text(if object.label.is_empty() {
                        "Unnamed object"
                    } else {
                        &object.label
                    })
                    .wrapping(text::Wrapping::WordOrGlyph),
                )
                .arrows()
                .width(Length::Fill)
                .style(if state.selected_object == Some(object.id) {
                    crate::ui::theme::selected
                } else {
                    crate::ui::theme::navigation
                })
                .on_press_maybe(enabled.then_some(Message::SelectObject(object.id)))
                .into()
            },
        )
        .width(Length::FillPortion(2)),
        iced::widget::table::column(
            sort_object(state, "Class", crate::ui::ObjectSort::Class),
            |object: &crate::backend::ObjectEntry| -> Element<'_, Message> {
                text(object.class_name()).size(14).into()
            },
        )
        .width(Length::Fill),
        iced::widget::table::column(
            sort_object(state, "ID", crate::ui::ObjectSort::Identifier),
            |object: &crate::backend::ObjectEntry| -> Element<'_, Message> {
                text(&object.identifier)
                    .font(iced::Font::MONOSPACE)
                    .size(14)
                    .into()
            },
        )
        .width(Length::Fill),
    ];
    let mut list = column![
        iced::widget::table(columns, entries)
            .padding(4)
            .separator_x(0)
            .separator_y(1)
    ]
    .spacing(12);
    if count == 0 {
        list = list.push(text(if !state.objects_loaded {
            "Reading objects, or refresh to retry a failed read."
        } else if state.objects.is_empty() {
            "No persistent objects are visible to the current role."
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
            detail = detail.push(text("Object locator").size(18)).push(
                text(uri)
                    .font(iced::Font::MONOSPACE)
                    .wrapping(text::Wrapping::Glyph),
            );
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
            .spacing(10)
            .wrap(),
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
                    .spacing(10)
                    .wrap(),
                );
            }
            _ => {}
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
    } else {
        detail = detail.push(text("Select an object to read its metadata."));
    }
    let toolbar = row![
        text_input("Filter label, class, ID or locator", &state.object_filter)
            .id("object-filter")
            .on_input(Message::ObjectFilter),
        button("Refresh Objects").on_press_maybe(enabled.then_some(Message::RefreshObjects))
    ]
    .spacing(12)
    .align_y(iced::Alignment::End);
    let browser = browser(state, list.into(), detail.into());
    column![
        toolbar,
        text(format!(
            "{count} of {} objects · visible to the current role",
            state.objects.len()
        ))
        .size(14),
        browser
    ]
    .spacing(12)
    .height(Length::Fill)
    .into()
}

fn sort_object<'a>(
    state: &UiState,
    label: &'a str,
    sort: crate::ui::ObjectSort,
) -> Element<'a, Message> {
    let suffix = if state.presentation.object_sort == sort {
        if state.presentation.object_descending {
            " ↓"
        } else {
            " ↑"
        }
    } else {
        ""
    };
    button(text(format!("{label}{suffix}")).size(14))
        .style(crate::ui::theme::navigation)
        .on_press(Message::Ui(crate::ui::Action::SortObjects(sort)))
        .into()
}

fn mechanisms(state: &UiState) -> Element<'_, Message> {
    let entries = crate::ui::sorted_mechanisms(state);
    let count = entries.len();
    let columns = [
        iced::widget::table::column(
            sort_mechanism(state, "Name", crate::ui::MechanismSort::Name),
            |entry: &crate::backend::MechanismEntry| -> Element<'_, Message> {
                button(text(&entry.name).font(iced::Font::MONOSPACE).size(14))
                    .arrows()
                    .width(Length::Fill)
                    .style(if state.selected_mechanism == Some(entry.id) {
                        crate::ui::theme::selected
                    } else {
                        crate::ui::theme::navigation
                    })
                    .on_press(Message::SelectMechanism(entry.id))
                    .into()
            },
        )
        .width(Length::FillPortion(3)),
        iced::widget::table::column(
            sort_mechanism(state, "Identifier", crate::ui::MechanismSort::Identifier),
            |entry: &crate::backend::MechanismEntry| -> Element<'_, Message> {
                text(&entry.identifier)
                    .font(iced::Font::MONOSPACE)
                    .size(14)
                    .into()
            },
        )
        .width(Length::Fill),
    ];
    let mut list = column![
        iced::widget::table(columns, entries)
            .padding(4)
            .separator_x(0)
            .separator_y(1)
    ]
    .spacing(12);
    if count == 0 {
        list = list.push(text(if !state.mechanisms_loaded {
            "Reading mechanisms, or refresh to retry a failed read."
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
                .id("mechanism-filter")
                .on_input(Message::MechanismFilter),
            button("Refresh Mechanisms")
                .on_press_maybe(state.can_submit().then_some(Message::RefreshMechanisms))
        ]
        .spacing(12)
        .align_y(iced::Alignment::End),
        text(format!("{count} of {} mechanisms", state.mechanisms.len())).size(14),
        browser(state, list.into(), detail.into()),
    ]
    .spacing(12)
    .height(Length::Fill)
    .into()
}

fn sort_mechanism<'a>(
    state: &UiState,
    label: &'a str,
    sort: crate::ui::MechanismSort,
) -> Element<'a, Message> {
    let suffix = if state.presentation.mechanism_sort == sort {
        if state.presentation.mechanism_descending {
            " ↓"
        } else {
            " ↑"
        }
    } else {
        ""
    };
    button(text(format!("{label}{suffix}")).size(14))
        .style(crate::ui::theme::navigation)
        .on_press(Message::Ui(crate::ui::Action::SortMechanisms(sort)))
        .into()
}
fn browser<'a>(
    state: &UiState,
    list: Element<'a, Message>,
    detail: Element<'a, Message>,
) -> Element<'a, Message> {
    if state.presentation.width - 268.0 >= 760.0 {
        row![
            container(scrollable(list).spacing(8)).width(Length::FillPortion(3)),
            container(scrollable(detail).spacing(8))
                .padding(16)
                .style(crate::ui::theme::surface)
                .width(Length::FillPortion(2))
        ]
        .spacing(16)
        .height(Length::Fill)
        .into()
    } else if state.presentation.show_detail {
        column![
            button("Back to List").on_press(Message::Ui(crate::ui::Action::BackToList)),
            scrollable(detail).spacing(8)
        ]
        .spacing(12)
        .height(Length::Fill)
        .into()
    } else {
        scrollable(list).spacing(8).height(Length::Fill).into()
    }
}
