// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    app::Message,
    backend::KeyProfile,
    state::{HkdfOutputChoice, KeyField, UiState},
    ui::{button, components::EMPHASIS, pick_list, text_input},
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
    let edit = move |field, value| Message::KeyEdit { id, field, value };
    let mut content = column![text("Derive an HKDF key").size(22).font(EMPHASIS)].spacing(10);
    if let Some(KeyProfile::Hkdf(profile)) = form.profile {
        let digest = match profile.digest {
            pkcs11_client::DigestAlgorithm::Sha256 => "SHA-256",
            pkcs11_client::DigestAlgorithm::Sha384 => "SHA-384",
            pkcs11_client::DigestAlgorithm::Sha512 => "SHA-512",
        };
        content = content.push(text(format!("HKDF {digest} extract-and-expand on a {}-byte token secret. The hash matches the base-key length. No key values leave the token; provider support is checked again before derivation.", profile.input_length)).size(14));
    } else {
        content = content.push(text(if form.loaded {
            "No permitted SHA-2 HKDF profile is available for this base key."
        } else {
            "Reading HKDF capabilities…"
        }));
    }
    content = content.push(
        pick_list(
            HkdfOutputChoice::ALL.as_slice(),
            Some(form.hkdf.output),
            move |output| Message::HkdfOutput { id, output },
        )
        .placeholder("Output key purpose")
        .enabled(enabled),
    );
    if form.hkdf.output == HkdfOutputChoice::DerivationSecret {
        content = content.push(
            text_input("New derivation secret length (bytes)", &form.hkdf.length)
                .on_input_maybe(enabled.then_some(move |value| edit(KeyField::Length, value))),
        );
        if let Some(KeyProfile::Hkdf(profile)) = form.profile {
            content = content.push(text(format!("Length: 1–{} bytes. Further HKDF use requires a base of the chosen hash's exact length.", 255 * profile.digest.output_len())).size(14));
        }
    }
    for (field, label, value) in [
        (
            KeyField::Salt,
            "Public salt (hexadecimal, optional, up to 4096 bytes)",
            &form.hkdf.salt,
        ),
        (
            KeyField::Info,
            "Protocol context (UTF-8, optional, up to 4096 bytes)",
            &form.hkdf.info,
        ),
        (KeyField::Label, "New secret key label", &form.label),
        (
            KeyField::Id,
            "New secret key ID (hexadecimal)",
            &form.key_id,
        ),
    ] {
        content = content.push(
            text_input(label, value)
                .on_input_maybe(enabled.then_some(move |value| edit(field, value))),
        );
    }
    content = content.push(text("Salt and context are public protocol inputs, not credentials. An empty salt uses RFC 5869 zero salt. Authenticate the peer and agree on the exact salt, context and output profile separately. This operation is not a hybrid combiner or TLS key schedule.").size(14));
    content = content.push(text("Creates a persistent private, sensitive, nonextractable key. AES outputs permit encryption/decryption only; generic outputs permit further derivation only. Label and ID: 1–128 bytes each. Existing secret IDs are rejected. A failed call or session close may still leave an object. The provider may reject an output template. No retry or rollback is performed.").size(14));
    content = content.push(
        row![
            button("Derive once").style(button::primary).on_press_maybe(
                (enabled
                    && form
                        .profile
                        .is_some_and(|profile| profile.supports(form.scope.mode)))
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
