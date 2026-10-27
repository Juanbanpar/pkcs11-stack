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
use pkcs11_client::KbkdfMode;

pub fn view(state: &UiState) -> Element<'_, Message> {
    let Some(form) = &state.key_form else {
        return column![].into();
    };
    let id = form.id;
    let enabled = state.can_submit();
    let mut content = column![text("Derive an SP 800-108 key").size(22).font(EMPHASIS)].spacing(10);
    let options = match form.profile {
        Some(KeyProfile::Kbkdf(options)) => Some(options),
        _ => None,
    };
    let modes: Vec<_> = KbkdfMode::ALL
        .into_iter()
        .filter(|mode| options.and_then(|o| o.get(*mode)).is_some())
        .collect();
    content = content.push(
        pick_list(modes, Some(form.kbkdf.mode), move |mode| {
            Message::KbkdfMode { id, mode }
        })
        .placeholder("SP800-108 mode")
        .enabled(enabled && options.is_some()),
    );
    let algorithms: Vec<_> = KbkdfDigest::ALL
        .into_iter()
        .filter(|d| {
            options
                .and_then(|o| o.get(form.kbkdf.mode))
                .is_some_and(|caps| caps.supports(d.0))
        })
        .collect();
    let description = match options.and_then(|o| o.get(form.kbkdf.mode)) {
        Some(caps) => format!(
            "{}-byte sensitive, nonextractable base key. Both modes use a 32-bit big-endian counter, a zero separator and a 32-bit output length in bits. Support and permissions are checked again before deriving.",
            caps.input_length,
        ),
        _ if form.loaded => "No permitted SP800-108 profile is available.".into(),
        _ => "Reading SP800-108 capabilities…".into(),
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
    if form.kbkdf.mode == KbkdfMode::Feedback {
        content = content.push(text("Feedback prepends the previous PRF output. An omitted IV supplies no initial bytes; a supplied IV must match the hash length.").size(14));
        content = content.push(
            text_input(
                "Feedback IV (hexadecimal, optional, 32/48/64 bytes matching the hash)",
                &form.kbkdf.iv,
            )
            .on_input_maybe(enabled.then_some(move |value| Message::KeyEdit {
                id,
                field: KeyField::KdfIv,
                value,
            })),
        );
    }
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
