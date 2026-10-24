// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::ui::{button, checkbox, components::EMPHASIS, pick_list, text_input};
use crate::{
    app::Message,
    backend::CryptoMode,
    state::{CryptoField, UiState},
};
use iced::{
    Element,
    widget::{column, container, row, text},
};
use secrecy::ExposeSecret;

pub fn view(state: &UiState) -> Element<'_, Message> {
    let Some(form) = &state.crypto_form else {
        return column![].into();
    };
    let id = form.id;
    let sign = form.scope.mode == CryptoMode::Sign;
    let enabled = state.can_submit();
    let edit = move |field, value| Message::CryptoEdit { id, field, value };
    let browse = move |field| Message::CryptoBrowse { id, field };
    let mut content = column![
        text(if sign { "Sign a file" } else { "Verify a signature" }).size(22).font(EMPHASIS),
        text(if sign { "Signs once with the selected private-key locator. No certificate association is checked." }
            else { "Verifies in software against the selected certificate's public key. Certificate trust is not checked." }).size(14),
        pick_list(form.options.as_slice(), form.choice, move |choice| Message::CryptoChoice { id, choice }).placeholder("Signature parameters").enabled(enabled),
    ].spacing(10);
    if !form.loaded {
        content = content.push(text("Reading supported choices…"));
    } else if form.options.is_empty() {
        content = content.push(text(
            "No supported signature choices under the selected policy.",
        ));
    }
    if sign {
        content = content.push(
            checkbox(form.software_hashing)
                .label("Allow software hashing if token hashing is unavailable")
                .on_toggle_maybe(
                    enabled.then_some(move |software| Message::CryptoPolicy { id, software }),
                ),
        );
        if let Some(choice) = form.choice
            && let Some((mechanism, hashing)) = choice.0.plan
        {
            let hashing = match hashing {
                pkcs11_client::HashLocation::Token => "Hashing on the token",
                pkcs11_client::HashLocation::Software => "Software hashing",
                pkcs11_client::HashLocation::Caller => "Caller-supplied digest",
            };
            content = content.push(crate::ui::components::muted(format!(
                "{hashing} · {mechanism}. Capabilities are checked again when signing."
            )));
        }
    }
    content = content
        .push(
            row![
                text_input("Message file (up to 16 MiB)", &form.input).on_input_maybe(
                    enabled.then_some(move |value| edit(CryptoField::Input, value))
                ),
                button("Browse…").on_press_maybe(
                    (enabled && form.picker.is_none()).then_some(browse(CryptoField::Input))
                ),
            ]
            .spacing(10)
            .align_y(iced::Alignment::End),
        )
        .push(
            row![
                text_input(
                    if sign {
                        "New signature output file"
                    } else {
                        "Signature file (up to 16 KiB)"
                    },
                    &form.signature
                )
                .on_input_maybe(
                    enabled.then_some(move |value| edit(CryptoField::Signature, value))
                ),
                button(if sign { "Save as…" } else { "Browse…" }).on_press_maybe(
                    (enabled && form.picker.is_none()).then_some(browse(CryptoField::Signature))
                ),
            ]
            .spacing(10)
            .align_y(iced::Alignment::End),
        );
    if sign && form.loaded && form.context_required {
        content = content.push(text("This key requires authentication for each operation."));
        if state.token().is_some_and(|token| token.protected_path) {
            content = content.push(
                checkbox(form.protected_path)
                    .label("Use token's protected authentication path")
                    .on_toggle_maybe(
                        enabled.then_some(move |enabled| Message::CryptoProtected { id, enabled }),
                    ),
            );
        }
        if form.protected_path {
            content = content.push(text("Complete authentication on the token when prompted."));
        } else {
            content = content.push(
                text_input("Per-operation PIN", form.pin.expose_secret())
                    .secure(true)
                    .on_input_maybe(enabled.then_some(move |pin: String| Message::CryptoPin {
                        id,
                        pin: pin.into(),
                    })),
            );
        }
        content = content
            .push(text("One attempt only. Failed authentication can lock the PIN.").size(14));
    }
    content = content.push(text(if sign {
        "Output uses raw RSA bytes or fixed-width ECDSA r || s, not DER. Existing files are never overwritten; a failed operation may leave an empty or partial file."
    } else { "Signature encoding must be raw RSA or fixed-width ECDSA r || s, not DER. PSS uses the displayed salt length and matching MGF1 digest." }).size(14))
        .push(row![button(if sign { "Sign once" } else { "Verify" }).style(button::primary).on_press_maybe((enabled && form.choice.is_some()).then_some(Message::SubmitCrypto(id))), button("Cancel").on_press(Message::DismissCrypto(id))].spacing(10).align_y(iced::Alignment::End));
    container(content)
        .padding(18)
        .style(crate::ui::theme::surface)
        .into()
}
