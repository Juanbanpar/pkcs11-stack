// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    app::Message,
    backend::KeyProfile,
    state::{HkdfOutputChoice, KbkdfDigest, KeyField, UiState},
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
    let mut content = column![text("Derive an SP 800-108 key").size(22).font(EMPHASIS)].spacing(10);
    let algorithms: Vec<_> = KbkdfDigest::ALL
        .into_iter()
        .filter(|d| matches!(form.profile,Some(KeyProfile::Kbkdf(caps)) if caps.supports(d.0)))
        .collect();
    let description = match form.profile {
        Some(KeyProfile::Kbkdf(caps)) => format!(
            "{}-byte sensitive, nonextractable base key. Counter mode uses a 32-bit big-endian counter, a zero separator and a 32-bit output length in bits. Support and permissions are checked again before deriving.",
            caps.input_length,
        ),
        _ if form.loaded => "No permitted counter-mode profile is available.".into(),
        _ => "Reading counter-mode capabilities…".into(),
    };
    content = content.push(text(description).size(14));
    content = content.push(
        pick_list(algorithms, Some(form.kbkdf.digest), move |digest| {
            Message::KbkdfDigest { id, digest }
        })
        .placeholder("SP800-108 PRF")
        .enabled(enabled && form.profile.is_some()),
    );
    content = content.push(
        pick_list(
            HkdfOutputChoice::ALL,
            Some(form.kbkdf.output),
            move |output| Message::KbkdfOutput { id, output },
        )
        .placeholder("Output key purpose")
        .enabled(enabled),
    );
    for (field, label, value) in [
        (
            KeyField::Length,
            "New derivation secret length (1–4096 bytes)",
            &form.kbkdf.length,
        ),
        (
            KeyField::KdfLabel,
            "KDF label (UTF-8, optional, up to 4096 bytes)",
            &form.kbkdf.kdf_label,
        ),
        (
            KeyField::Info,
            "Protocol context (UTF-8, optional, up to 4096 bytes)",
            &form.kbkdf.context,
        ),
        (KeyField::Label, "New secret key label", &form.label),
        (
            KeyField::Id,
            "New secret key ID (hexadecimal)",
            &form.key_id,
        ),
    ] {
        if field == KeyField::Length && form.kbkdf.output != HkdfOutputChoice::DerivationSecret {
            continue;
        }
        content =
            content.push(text_input(label, value).on_input_maybe(
                enabled.then_some(move |value| Message::KeyEdit { id, field, value }),
            ));
    }
    content = content.push(text("Agree on the exact label/context encoding and output profile with the peer. The KDF label is a protocol input, separate from the new object's label. This operation does not authenticate peers.").size(14));
    content = content.push(text("Creates one persistent private, sensitive, nonextractable key. AES outputs permit encryption/decryption; generic outputs permit further derivation. Label and ID: 1–128 bytes each. Existing secret IDs are rejected. Failure can leave an object; no retry or rollback.").size(14));
    content = content.push(
        row![
            button("Derive once").style(button::primary).on_press_maybe(
                (enabled && form.profile.is_some()).then_some(Message::SubmitKeyOperation(id))
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
