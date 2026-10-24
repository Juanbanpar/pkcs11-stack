// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::ui::{button, components::EMPHASIS, pick_list, text_input};
use crate::{
    app::Message,
    backend::CryptoMode,
    state::{CipherField, UiState},
};
use iced::{
    Element,
    widget::{column, container, row, text},
};
pub fn view(state: &UiState) -> Element<'_, Message> {
    let Some(form) = &state.cipher_form else {
        return column![].into();
    };
    let id = form.id;
    let encrypt = form.scope.mode == CryptoMode::Encrypt;
    let enabled = state.can_submit();
    let mut content = column![
        text(if encrypt { "Encrypt a small payload" } else { "Decrypt RSA OAEP" }).size(22).font(EMPHASIS),
        text("RSA-OAEP uses the selected SHA-2 digest for both OAEP and MGF1, with an empty label. It handles one RSA block; large-file encryption is not supported.").size(14),
        pick_list(form.choices.as_slice(), form.choice, move |choice| Message::CipherChoice { id, choice }).placeholder("OAEP digest").enabled(enabled),
    ].spacing(10);
    if let Some(choice) = form.choice {
        content = content.push(text(format!("Maximum plaintext: {} bytes · ciphertext: exactly {} bytes. Choices are advisory; a provider may reject digest parameters.", choice.0.maximum_plaintext, choice.0.ciphertext_length)).size(14));
    } else {
        content = content.push(text(if form.loaded {
            "No supported OAEP choice."
        } else {
            "Reading permitted OAEP choices…"
        }));
    }
    content = content.push(row![
        text_input(if encrypt { "Plaintext input file" } else { "Raw ciphertext input file" }, &form.input).on_input_maybe(enabled.then_some(move |value| Message::CipherEdit { id, field: CipherField::Input, value })),
        button("Browse…").on_press_maybe((enabled && form.picker.is_none()).then_some(Message::CipherBrowse { id, field: CipherField::Input })),
    ].spacing(10).align_y(iced::Alignment::End)).push(row![
        text_input("New output file", &form.output).on_input_maybe(enabled.then_some(move |value| Message::CipherEdit { id, field: CipherField::Output, value })),
        button("Save as…").on_press_maybe((enabled && form.picker.is_none()).then_some(Message::CipherBrowse { id, field: CipherField::Output })),
    ].spacing(10).align_y(iced::Alignment::End)).push(text("Output files are never overwritten. A failed operation can leave an empty or partial file. Each submission runs once, without a padding downgrade or retry.").size(14))
        .push(row![button(if encrypt { "Encrypt once" } else { "Decrypt once" }).style(button::primary).on_press_maybe((enabled && form.choice.is_some()).then_some(Message::SubmitCipher(id))), button("Cancel").on_press(Message::DismissCipher(id))].spacing(10).align_y(iced::Alignment::End));
    container(content)
        .padding(18)
        .style(crate::ui::theme::surface)
        .into()
}
