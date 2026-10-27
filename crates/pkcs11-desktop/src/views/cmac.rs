// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    app::Message,
    backend::{CryptoMode, KeyProfile},
    state::{KeyField, UiState},
    ui::{button, components::EMPHASIS, text_input},
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
    let verify = form.scope.mode == CryptoMode::VerifyMac;
    let enabled = state.can_submit();
    let mut content = column![
        text(if verify {
            "Verify an AES-CMAC tag"
        } else {
            "Create an AES-CMAC tag"
        })
        .size(22)
        .font(EMPHASIS)
    ]
    .spacing(10);
    content = content.push(text(if let Some(KeyProfile::AesCmac(caps)) = form.profile {
        format!("AES-{} with a full 16-byte tag. The sensitive, nonextractable key stays on the token. Native support and permissions are checked again before use.", caps.key_size.length() * 8)
    } else if form.loaded { "No permitted AES-CMAC profile is available for this operation.".into() } else { "Reading AES-CMAC capabilities…".into() }).size(14));
    for (field, placeholder, value) in [
        (KeyField::Input, "Message file (up to 16 MiB)", &form.input),
        (
            KeyField::Output,
            if verify {
                "Tag input file (exactly 16 bytes)"
            } else {
                "New tag output file"
            },
            &form.output,
        ),
    ] {
        content = content.push(
            row![
                text_input(placeholder, value).on_input_maybe(
                    enabled.then_some(move |value| Message::KeyEdit { id, field, value })
                ),
                button(if field == KeyField::Output && !verify {
                    "Save as…"
                } else {
                    "Browse…"
                })
                .on_press_maybe(
                    (enabled && form.picker.is_none()).then_some(Message::KeyBrowse { id, field })
                )
            ]
            .spacing(10)
            .align_y(iced::Alignment::End),
        );
    }
    content = content.push(text(if verify { "Verify the exact message and full tag with the shared key. A matching tag authenticates possession of that key; it does not identify an individual signer." } else { "Empty messages are allowed. Only the raw tag is written, after session closure succeeds. Existing files are never overwritten; failure may leave an empty or partial file." }).size(14));
    content = content.push(
        row![
            button(if verify { "Verify tag" } else { "Create tag" })
                .style(button::primary)
                .on_press_maybe(
                    (enabled && form.profile.is_some_and(|p| p.supports(form.scope.mode)))
                        .then_some(Message::SubmitKeyOperation(id))
                ),
            button("Cancel").on_press(Message::DismissKeyOperation(id))
        ]
        .spacing(10),
    );
    container(content)
        .padding(18)
        .style(crate::ui::theme::surface)
        .into()
}
