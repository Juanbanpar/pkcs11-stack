// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::ui::{button, components::EMPHASIS, pick_list, text_input};
use crate::{
    app::Message,
    backend::{CipherParameters, CryptoMode},
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
    let aes = state
        .object()
        .is_some_and(|object| object.class == Some(pkcs11_client::ObjectClass::SECRET_KEY));
    let enabled = state.can_submit();
    let mut content = column![
        text(if aes {
            if encrypt { "Encrypt AES-GCM" } else { "Decrypt AES-GCM" }
        } else if encrypt { "Encrypt a small payload" } else { "Decrypt RSA OAEP" }).size(22).font(EMPHASIS),
        text(if aes {
            "AES-GCM supports up to 16 MiB of plaintext and 1 MiB of AAD. Ciphertext includes a full 16-byte tag; the nonce and AAD are separate."
        } else {
            "RSA-OAEP uses the selected SHA-2 digest for both OAEP and MGF1, with an empty label. It handles one RSA block; large-file encryption is not supported."
        }).size(14),
    ].spacing(10);
    if !aes {
        content = content.push(
            pick_list(form.choices.as_slice(), form.choice, move |choice| {
                Message::CipherChoice { id, choice }
            })
            .placeholder("OAEP digest")
            .enabled(enabled),
        );
    }
    match form.choice.map(|choice|choice.0) {
        Some(CipherParameters::Oaep(choice)) => content = content.push(text(format!("Maximum plaintext: {} bytes · ciphertext: exactly {} bytes. Choices are advisory; a provider may reject digest parameters.",choice.maximum_plaintext,choice.ciphertext_length)).size(14)),
        Some(CipherParameters::AesGcm(caps)) => content = content.push(text(format!("AES-{} GCM · 12-byte nonce · 128-bit tag. Provider support is checked again before execution.",caps.key_size.length()*8)).size(14)),
        None => content = content.push(text(if form.loaded { "No supported cipher choice." } else { "Reading permitted cipher choices…" })),
    }
    if aes {
        content = content.push(text_input("Nonce (24 hexadecimal digits)",&form.nonce).on_input_maybe(enabled.then_some(move |value|Message::CipherEdit { id,field: CipherField::Nonce,value })))
            .push(text(if encrypt { "Use a nonce never previously used with this key, across applications and restarts. After an encryption error, use a new nonce." } else { "Supply the encryption nonce and the exact AAD. Authentication failure writes no plaintext." }).size(14))
            .push(row![
                text_input("AAD file (optional)",&form.aad).on_input_maybe(enabled.then_some(move |value|Message::CipherEdit { id,field: CipherField::Aad,value })),
                button("Browse AAD…").on_press_maybe((enabled && form.picker.is_none()).then_some(Message::CipherBrowse { id,field: CipherField::Aad })),
            ].spacing(10).align_y(iced::Alignment::End));
    }
    content = content.push(row![
        text_input(if encrypt { "Plaintext input file" } else { "Raw ciphertext input file" },&form.input).on_input_maybe(enabled.then_some(move |value|Message::CipherEdit { id,field: CipherField::Input,value })),
        button("Browse…").on_press_maybe((enabled && form.picker.is_none()).then_some(Message::CipherBrowse { id,field: CipherField::Input })),
    ].spacing(10).align_y(iced::Alignment::End)).push(row![
        text_input("New output file",&form.output).on_input_maybe(enabled.then_some(move |value|Message::CipherEdit { id,field: CipherField::Output,value })),
        button("Save as…").on_press_maybe((enabled && form.picker.is_none()).then_some(Message::CipherBrowse { id,field: CipherField::Output })),
    ].spacing(10).align_y(iced::Alignment::End)).push(text("Output files are never overwritten. A failed operation can leave an empty or partial file. Each submission runs once, without a downgrade or retry.").size(14))
        .push(row![button(if encrypt { "Encrypt once" } else { "Decrypt once" }).style(button::primary).on_press_maybe((enabled && form.choice.is_some()).then_some(Message::SubmitCipher(id))),button("Cancel").on_press(Message::DismissCipher(id))].spacing(10).align_y(iced::Alignment::End));
    container(content)
        .padding(18)
        .style(crate::ui::theme::surface)
        .into()
}
