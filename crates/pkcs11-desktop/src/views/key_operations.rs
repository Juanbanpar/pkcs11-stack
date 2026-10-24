// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::ui::{button, pick_list, text_input};
use crate::{
    app::Message,
    backend::CryptoMode,
    state::{KeyField, UiState},
};
use iced::{
    Element,
    widget::{column, container, row, text},
};
pub fn view(state: &UiState) -> Element<'_, Message> {
    let Some(form) = &state.key_form else {
        return column![].into();
    };
    let id = form.id;
    let enabled = state.can_submit();
    let wrap = form.scope.mode == CryptoMode::Wrap;
    let derive = form.scope.mode == CryptoMode::Derive;
    let title = if derive {
        "Derive an ECDH shared secret"
    } else if wrap {
        "Wrap an AES key"
    } else {
        "Unwrap an AES key"
    };
    let mut content = column![text(title).size(22)].spacing(10);
    if let Some(profile) = form.profile {
        content = content.push(text(match profile {
            pkcs11_client::KeyOperationProfile::EcdhRaw(curve) => format!("Raw ECDH {curve:?} with an explicit null KDF. The token-held shared secret requires a later KDF before cryptographic use. Authenticate the peer public key separately."),
            pkcs11_client::KeyOperationProfile::AesKeyWrap(bytes) => format!("RFC 3394 AES key wrap with the default IV, using an AES-{} key. The blob contains no label, ID or permissions.", bytes * 8),
        }).size(14));
    } else {
        content = content.push(text(if form.loaded {
            "This key has no permitted profile for this operation."
        } else {
            "Reading permitted key operation profile…"
        }));
    }
    if wrap {
        content = content.push(pick_list(form.targets.clone(), form.target.clone(), move |target| Message::KeyTarget { id, target }).placeholder("Target secret key").enabled(enabled))
            .push(text("Candidates are secret keys. The client checks AES type, extractability and wrapping trust policy before wrapping; it never changes those permissions.").size(14));
    } else {
        content = content.push(
            row![
                text_input(
                    if derive {
                        "Peer public key file (SPKI DER)"
                    } else {
                        "Wrapped AES input file (24/32/40 bytes)"
                    },
                    &form.input
                )
                .on_input_maybe(enabled.then_some(move |value| Message::KeyEdit {
                    id,
                    field: KeyField::Input,
                    value
                })),
                button("Browse…").on_press_maybe((enabled && form.picker.is_none()).then_some(
                    Message::KeyBrowse {
                        id,
                        field: KeyField::Input
                    }
                ))
            ]
            .spacing(10)
            .align_y(iced::Alignment::End),
        );
        for (field, placeholder, value) in [
            (KeyField::Label, "New secret key label", &form.label),
            (
                KeyField::Id,
                "New secret key ID (hexadecimal)",
                &form.key_id,
            ),
        ] {
            content = content.push(text_input(placeholder, value).on_input_maybe(
                enabled.then_some(move |value| Message::KeyEdit { id, field, value }),
            ));
        }
        content = content.push(text(if derive { "Creates a persistent sensitive, nonextractable generic secret with derivation permission only. No encryption, decryption, signing or wrapping is allowed. Existing secret key IDs are rejected. Failure may leave an object; refresh before retrying." } else { "Creates a persistent private sensitive, nonextractable AES key with encryption/decryption permission only. Existing secret key IDs are rejected. Failure may leave an object; refresh before retrying." }).size(14));
    }
    if wrap {
        content = content.push(row![text_input("New wrapped output file", &form.output).on_input_maybe(enabled.then_some(move |value| Message::KeyEdit { id, field: KeyField::Output, value })), button("Save as…").on_press_maybe((enabled && form.picker.is_none()).then_some(Message::KeyBrowse { id, field: KeyField::Output }))].spacing(10).align_y(iced::Alignment::End))
            .push(text("Existing files are never overwritten. Failure may leave an empty or partial output file.").size(14));
    }
    content = content.push(
        row![
            button(if derive {
                "Derive once"
            } else if wrap {
                "Wrap once"
            } else {
                "Unwrap once"
            })
            .style(button::primary)
            .on_press_maybe(
                (enabled && form.profile.is_some()).then_some(Message::SubmitKeyOperation(id))
            ),
            button("Cancel").on_press(Message::DismissKeyOperation(id))
        ]
        .spacing(10)
        .align_y(iced::Alignment::End),
    );
    container(content)
        .padding(12)
        .style(crate::ui::theme::surface)
        .into()
}
