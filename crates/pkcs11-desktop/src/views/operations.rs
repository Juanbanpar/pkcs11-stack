// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    app::Message,
    state::{ManagementField, UiState},
};
use iced::{
    Element,
    widget::{button, checkbox, column, pick_list, row, rule, text, text_input},
};

pub fn view(state: &UiState) -> Element<'_, Message> {
    let enabled = state.can_manage();
    let edit = |field, value| Message::ManagementEdit { field, value };
    let hint = if enabled {
        "New objects persist on the token. Labels and IDs can collide with existing objects."
    } else {
        "Log in as USER on a writable token to generate keys, import certificates or delete objects."
    };
    let choices = if state.management.capabilities_loaded && state.management.keys.is_empty() {
        "No supported key-generation choices are advertised."
    } else {
        "Choices reflect provider flags and bounds; a vendor may reject a specific template."
    };
    column![
        text(hint),
        text("Generate signing key pair").size(22),
        row![pick_list(state.management.keys.as_slice(), state.management.key, Message::GenerationKey).placeholder("Key type"),
            button("Refresh choices").on_press_maybe(state.can_submit().then_some(Message::ReadCapabilities))].spacing(10),
        text(choices).size(14),
        text_input("Key label", &state.management.key_label).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::KeyLabel, value))),
        text_input("Key ID (hexadecimal bytes)", &state.management.key_id).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::KeyId, value))),
        checkbox(state.management.always_authenticate).label("Require authentication for every private-key operation")
            .on_toggle_maybe(enabled.then_some(Message::AlwaysAuthenticate)),
        text("Private keys are sensitive and nonextractable; the public key shares the label and ID.").size(14),
        button("Generate pair").on_press_maybe((enabled && state.management.key.is_some()).then_some(Message::Generate)),
        rule::horizontal(1),
        text("Import X.509 certificate").size(22),
        row![text_input("DER certificate file", &state.management.certificate_path).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::CertificatePath, value))),
            button("Browse…").on_press_maybe((enabled && state.management.file_request.is_none()).then_some(Message::ChooseCertificate))].spacing(10),
        text_input("Certificate label", &state.management.certificate_label).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::CertificateLabel, value))),
        text_input("Certificate ID (hexadecimal bytes)", &state.management.certificate_id).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::CertificateId, value))),
        text("Import accepts one DER certificate up to 16 MiB. Parsing does not establish trust or bind it to a key.").size(14),
        button("Import certificate").on_press_maybe(enabled.then_some(Message::ImportCertificate)),
    ].spacing(12).into()
}
