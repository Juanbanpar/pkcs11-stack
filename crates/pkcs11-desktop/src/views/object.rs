// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    app::Message,
    backend::{CryptoMode, LoginState, MetadataField},
    state::UiState,
    ui::{
        button,
        components::{self, EMPHASIS, Tone, badge, muted},
        theme,
    },
};
use iced::{
    Element, Length,
    widget::{column, row, rule, text},
};
use pkcs11_client::ObjectClass;

pub fn detail(state: &UiState) -> Element<'_, Message> {
    let Some(object) = state.object() else {
        return components::empty(
            "Inspect an object",
            "Select an object to read its attributes and see available actions. Private objects appear after USER login.",
        );
    };
    let mut content = column![
        badge(object.class_name(), Tone::Info),
        text(if object.label.is_empty() {
            "Unnamed object"
        } else {
            &object.label
        })
        .size(22)
        .font(EMPHASIS)
        .wrapping(text::Wrapping::WordOrGlyph),
        muted(format!(
            "ID {}",
            if object.identifier.is_empty() {
                "not reported"
            } else {
                &object.identifier
            }
        ))
        .font(iced::Font::MONOSPACE)
        .size(13),
    ]
    .spacing(12);
    if object.ambiguous {
        content = content.push(components::notice("Ambiguous identity", "Several objects share this locator. Actions and detail reads require an unambiguous object."));
    } else if object.uri.is_none() {
        content = content.push(components::notice(
            "Unsupported identity",
            "The reported attributes cannot form a supported locator for actions or detail reads.",
        ));
    }
    let mut actions = column![].spacing(8);
    match object.class {
        Some(ObjectClass::PRIVATE_KEY) => {
            actions = actions
                .push(
                    button("Sign file…")
                        .width(Length::Fill)
                        .style(button::primary)
                        .on_press_maybe(
                            state
                                .can_open_crypto(CryptoMode::Sign)
                                .then_some(Message::OpenCrypto(CryptoMode::Sign)),
                        ),
                )
                .push(
                    button("Decrypt RSA OAEP…")
                        .width(Length::Fill)
                        .on_press_maybe(
                            state
                                .can_open_cipher(CryptoMode::Decrypt)
                                .then_some(Message::OpenCipher(CryptoMode::Decrypt)),
                        ),
                )
                .push(
                    button("Derive ECDH secret…")
                        .width(Length::Fill)
                        .on_press_maybe(
                            state
                                .can_open_key_operation(CryptoMode::Derive)
                                .then_some(Message::OpenKeyOperation(CryptoMode::Derive)),
                        ),
                );
            if !state
                .token()
                .is_some_and(|token| token.login == LoginState::User)
            {
                actions = actions.push(muted("USER login is required to use this private key."));
            }
        }
        Some(ObjectClass::CERTIFICATE) => {
            actions = actions.push(
                button("Verify signature…")
                    .width(Length::Fill)
                    .style(button::primary)
                    .on_press_maybe(
                        state
                            .can_open_crypto(CryptoMode::Verify)
                            .then_some(Message::OpenCrypto(CryptoMode::Verify)),
                    ),
            )
        }
        Some(ObjectClass::PUBLIC_KEY) => {
            actions = actions.push(
                button("Encrypt RSA OAEP…")
                    .width(Length::Fill)
                    .style(button::primary)
                    .on_press_maybe(
                        state
                            .can_open_cipher(CryptoMode::Encrypt)
                            .then_some(Message::OpenCipher(CryptoMode::Encrypt)),
                    ),
            )
        }
        Some(ObjectClass::SECRET_KEY) => {
            actions = actions
                .push(
                    button("Wrap AES key…").width(Length::Fill).on_press_maybe(
                        state
                            .can_open_key_operation(CryptoMode::Wrap)
                            .then_some(Message::OpenKeyOperation(CryptoMode::Wrap)),
                    ),
                )
                .push(
                    button("Unwrap AES key…")
                        .width(Length::Fill)
                        .on_press_maybe(
                            state
                                .can_open_key_operation(CryptoMode::Unwrap)
                                .then_some(Message::OpenKeyOperation(CryptoMode::Unwrap)),
                        ),
                );
        }
        _ => {}
    }
    let identity_issues = object
        .fields
        .iter()
        .filter(|field| object.uri.is_none() || field.value.is_none());
    if identity_issues.clone().next().is_some() {
        content = content
            .push(text("Identity attributes").size(15).font(EMPHASIS))
            .push(metadata(identity_issues));
    }
    content = content.push(actions);
    if let Some(uri) = &object.uri {
        content = content.push(components::locator(state, uri));
    }

    if let Some(fields) = &state.object_details {
        content = content
            .push(rule::horizontal(1))
            .push(text("Attributes").size(15).font(EMPHASIS))
            .push(metadata(fields));
    } else if !object.ambiguous && object.uri.is_some() {
        content = content
            .push(muted("Attributes are read only when you select an object."))
            .push(
                button("Read attributes again")
                    .id("retry-object-details")
                    .on_press_maybe(
                        state
                            .can_submit()
                            .then_some(Message::SelectObject(object.id)),
                    ),
            );
    }
    let mut management = column![text("Object management").size(15).font(EMPHASIS)].spacing(8);
    if matches!(
        object.class,
        Some(ObjectClass::CERTIFICATE | ObjectClass::PUBLIC_KEY | ObjectClass::DATA)
    ) {
        management = management.push(
            button("Export public object…")
                .width(Length::Fill)
                .on_press_maybe(state.can_export().then_some(Message::ExportObject)),
        );
        if !state.can_export() {
            management = management.push(muted(
                "Export requires attributes confirming that this is a public object.",
            ));
        }
    }
    management = management.push(
        button("Delete object…")
            .width(Length::Fill)
            .style(theme::destructive_quiet)
            .on_press_maybe(
                (state.can_manage() && !object.ambiguous && object.uri.is_some())
                    .then_some(Message::RequestDelete),
            ),
    );
    if !state.can_manage() {
        management = management.push(muted("Deletion requires USER login on a writable token."));
    }
    content.push(rule::horizontal(1)).push(management).into()
}

fn metadata<'a>(fields: impl IntoIterator<Item = &'a MetadataField>) -> Element<'a, Message> {
    let mut content = column![].spacing(10);
    for field in fields {
        let value = field
            .value
            .as_deref()
            .map(|value| if value.is_empty() { "(empty)" } else { value })
            .unwrap_or(field.status);
        content = content.push(
            row![
                muted(field.name).size(13).width(Length::Fill),
                text(value)
                    .size(13)
                    .wrapping(text::Wrapping::WordOrGlyph)
                    .width(Length::Fill)
            ]
            .spacing(12),
        );
    }
    content.into()
}
