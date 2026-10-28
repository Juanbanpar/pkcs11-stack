// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::ui::{
    button, checkbox,
    components::{EMPHASIS, muted},
    pick_list, text_input, theme,
};
use crate::{
    app::Message,
    state::{ManagementField, PublicKeyPurposeChoice, RandomField, UiState},
};
use iced::{
    Element,
    widget::{column, container, row, text},
};
use iced_fonts::lucide;

pub fn view(state: &UiState) -> Element<'_, Message> {
    let enabled = state.can_manage();
    let edit = |field, value| Message::ManagementEdit { field, value };
    let hint = if enabled {
        "New objects persist on the token. Choose a label and hexadecimal ID."
    } else {
        "Log in as USER on a writable token to generate keys, import public objects or delete objects."
    };
    let choices = if state.management.capabilities_loaded && state.management.keys.is_empty() {
        "No supported key-generation choices are advertised."
    } else {
        "Choices reflect provider flags and bounds; a vendor may reject a specific template."
    };
    use crate::ui::{Action, ManagementTask};
    let Some(task) = state.presentation.task else {
        let requirement = if state.token().is_some_and(|token| token.write_protected) {
            "Read-only token"
        } else if state.token().is_some_and(|token| !token.initialized) {
            "Initialization required"
        } else if enabled {
            "USER session"
        } else {
            "USER login required"
        };
        let task_button = |icon: iced::widget::Text<'static>,
                           title: &'static str,
                           requirement: &'static str,
                           task| {
            button(
                row![
                    icon.size(20).style(theme::accent),
                    text(title)
                        .size(16)
                        .font(EMPHASIS)
                        .width(iced::Length::Fill),
                    muted(requirement).size(12),
                    lucide::chevron_right().size(16).style(theme::muted)
                ]
                .spacing(12)
                .align_y(iced::Alignment::Center),
            )
            .padding(10)
            .width(iced::Length::Fill)
            .style(theme::task_card)
            .on_press_maybe(
                state
                    .can_submit()
                    .then_some(Message::Ui(Action::Task(Some(task)))),
            )
        };
        return column![
            text("Operations").size(20).font(EMPHASIS),
            muted("Create objects here. For signing or key derivation, select an object."),
            task_button(
                lucide::key(),
                "Generate Key",
                requirement,
                ManagementTask::Generate
            ),
            task_button(
                lucide::upload(),
                "Import X.509 Certificate",
                requirement,
                ManagementTask::Import
            ),
            task_button(
                lucide::upload(),
                "Import RSA/EC/EdDSA Public Key",
                requirement,
                ManagementTask::ImportPublicKey
            ),
            task_button(
                lucide::upload(),
                "Import ML-KEM Public Key",
                requirement,
                ManagementTask::ImportMlKem
            ),
            task_button(
                lucide::file(),
                "Hash File on Token",
                "Advertised digest algorithms",
                ManagementTask::Digest
            ),
            task_button(
                lucide::shuffle(),
                "Generate Random Bytes",
                if state.can_random() {
                    "Token RNG"
                } else {
                    "RNG unavailable"
                },
                ManagementTask::Random
            ),
        ]
        .spacing(4)
        .max_width(850)
        .into();
    };
    let form: Element<'_, Message> = match task {
        ManagementTask::ImportPublicKey => column![
            text("Import RSA/EC/EdDSA public key").size(22).font(EMPHASIS), muted(hint),
            row![text_input("RSA/EC/EdDSA public key file (SPKI DER)", &state.management.public_key.path).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::PublicKeyPath, value))), button("Browse…").on_press_maybe((enabled && state.management.file_request.is_none()).then_some(Message::ChoosePublicKey))].spacing(10).align_y(iced::Alignment::End),
            pick_list(PublicKeyPurposeChoice::ALL, Some(state.management.public_key.purpose), Message::PublicKeyPurpose).enabled(enabled),
            text_input("Public key label (1–128 UTF-8 bytes)", &state.management.public_key.label).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::PublicKeyLabel, value))),
            text_input("Public key ID (1–128 hexadecimal bytes)", &state.management.public_key.id).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::PublicKeyId, value))),
            text("Accepts one SPKI DER public key up to 4096 bytes: RSA 2048–16384, P-256/P-384/P-521 or Ed25519/Ed448. Verification or RSA encryption permissions are explicit; wrapping, recovery and derivation are disabled. Existing public-key IDs are rejected. Import does not establish identity, private-key possession or association with other objects sharing the ID.").size(14),
            button("Import public key").style(button::primary).on_press_maybe(enabled.then_some(Message::ImportPublicKey)),
        ].spacing(12).into(),
        ManagementTask::ImportMlKem => column![
            text("Import ML-KEM public key").size(22).font(EMPHASIS), muted(hint),
            row![text_input("ML-KEM public key file (SPKI DER)", &state.management.ml_kem_path).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::MlKemPath, value))), button("Browse…").on_press_maybe((enabled && state.management.file_request.is_none()).then_some(Message::ChooseMlKem))].spacing(10).align_y(iced::Alignment::End),
            text_input("Public key label (1–128 UTF-8 bytes)", &state.management.ml_kem_label).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::MlKemLabel, value))),
            text_input("Public key ID (1–128 hexadecimal bytes)", &state.management.ml_kem_id).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::MlKemId, value))),
            text("Accepts one ML-KEM-512/768/1024 SPKI DER key, up to 2048 bytes. Authenticate the peer separately; importing a public key does not prove identity or possession of its private key. Existing objects are kept; duplicate IDs can make selection ambiguous.").size(14),
            button("Import public key").style(button::primary).on_press_maybe(enabled.then_some(Message::ImportMlKem)),
        ].spacing(12).into(),
        ManagementTask::Generate => column![
        text("Generate key").size(22).font(EMPHASIS),
        muted(hint),
        row![pick_list(state.management.keys.as_slice(), state.management.key, Message::GenerationKey).placeholder("Key type").enabled(enabled),
            button("Refresh choices").on_press_maybe(state.can_submit().then_some(Message::ReadCapabilities))].spacing(10),
        text(choices).size(14),
        text_input("Key label", &state.management.key_label).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::KeyLabel, value))),
        text_input("Key ID (hexadecimal bytes)", &state.management.key_id).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::KeyId, value))),
        checkbox(state.management.always_authenticate).label("Require authentication for every private-key operation")
            .on_toggle_maybe((enabled && state.management.key.is_some_and(|key| key.0.supports_context_authentication())).then_some(Message::AlwaysAuthenticate)),
        text(match state.management.key.map(|key| key.0) {
            Some(crate::backend::GenerationKind::Hmac(_)) => "Private, sensitive, nonextractable generic secret for the selected HMAC only. Signing/verification are enabled; encryption, wrapping and derivation are disabled. ID and label: 1–128 bytes each.",
            Some(crate::backend::GenerationKind::EdDsa(_)) => "EdDSA signing pair. The private key is sensitive and nonextractable. Sign original messages without an external digest.",
            Some(crate::backend::GenerationKind::MlDsa(_)) => "ML-DSA signing pair. The private key is sensitive and nonextractable. Select the private key on Objects to sign a file, or the public key to export it.",
            Some(crate::backend::GenerationKind::MlKem(_)) => "ML-KEM encapsulation/decapsulation pair. The private key is sensitive and nonextractable. Select either key on Objects for ML-KEM operations, or export the public key.",
            Some(crate::backend::GenerationKind::RsaEncryption(_)) => "Encryption/decryption-only RSA pair. The private key is sensitive and nonextractable; signing, wrapping and derivation are disabled. ID and label: 1–128 bytes each.",
            Some(crate::backend::GenerationKind::Ecdh(_)) => "Derivation-only EC pair. The private key is sensitive and nonextractable. ID and label: 1–128 bytes each.",
            Some(crate::backend::GenerationKind::Aes(_, pkcs11_client::AesKeyPurpose::Encryption)) => "Private, sensitive, nonextractable AES key for encryption/decryption only. ID and label: 1–128 bytes each.",
            Some(crate::backend::GenerationKind::Aes(_, pkcs11_client::AesKeyPurpose::Authentication)) => "Private, sensitive, nonextractable AES key for full-tag CMAC generation/verification only. ID and label: 1–128 bytes each.",
            Some(crate::backend::GenerationKind::Aes(_, pkcs11_client::AesKeyPurpose::Wrapping)) => "Private, sensitive, nonextractable AES key for wrapping/unwrapping only. Targets must permit export. ID and label: 1–128 bytes each.",
            _ => "Signing pair. The private key is sensitive and nonextractable; the public key shares its label and ID.",
        }).size(14),
        button("Generate key").style(button::primary).on_press_maybe((enabled && state.management.key.is_some()).then_some(Message::Generate)),
        ].spacing(12).into(),
        ManagementTask::Import => column![text("Import X.509 certificate").size(22).font(EMPHASIS), muted(hint),
        row![text_input("DER certificate file", &state.management.certificate_path).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::CertificatePath, value))),
            button("Browse…").on_press_maybe((enabled && state.management.file_request.is_none()).then_some(Message::ChooseCertificate))].spacing(10).align_y(iced::Alignment::End),
        text_input("Certificate label", &state.management.certificate_label).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::CertificateLabel, value))),
        text_input("Certificate ID (hexadecimal bytes)", &state.management.certificate_id).on_input_maybe(enabled.then_some(move |value| edit(ManagementField::CertificateId, value))),
        text("Import accepts one DER certificate up to 16 MiB. Parsing does not establish trust or bind it to a key.").size(14),
        button("Import certificate").style(button::primary).on_press_maybe(enabled.then_some(Message::ImportCertificate)),
        ].spacing(12).into(),
        ManagementTask::Digest => {
            let enabled = state.can_submit();
            let mut content = column![text("Hash a file on the token").size(22).font(EMPHASIS),
                text("Uses the selected token's hash mechanism with bounded input chunks. No key or software fallback is used. The provider may require login.").size(14),
                pick_list(state.digest.algorithms.clone(), state.digest.algorithm, Message::DigestAlgorithm).enabled(enabled),
                row![text_input("Input file", &state.digest.path).on_input_maybe(enabled.then_some(Message::DigestPath)), button("Browse…").on_press_maybe((enabled && state.digest.picker.is_none()).then_some(Message::DigestBrowse))].spacing(10).align_y(iced::Alignment::End),
                button("Hash file").style(button::primary).on_press_maybe(state.can_digest().then_some(Message::DigestFile))].spacing(12);
            if !state.digest.loaded { content = content.push(text("Reading advertised multipart digest algorithms…")); }
            else if state.digest.algorithms.is_empty() { content = content.push(text("No supported multipart digest algorithms are advertised.")); }
            if let Some(result) = &state.digest.result { content = content.push(text(result).font(iced::Font::MONOSPACE)); }
            content.into()
        }
        ManagementTask::Random => column![
        text("Generate token random bytes").size(22).font(EMPHASIS),
        text(if state.token().is_some_and(|token| token.can_random()) {
            "Uses this token's random generator. The provider may require login; no software fallback is used."
        } else { "This token does not advertise an available random generator." }).size(14),
        text_input("Byte count (1–1048576)", &state.random.length).on_input_maybe(state.can_random().then_some(|value| Message::RandomEdit { field: RandomField::Length, value })),
        row![text_input("New output file", &state.random.path).on_input_maybe(state.can_random().then_some(|value| Message::RandomEdit { field: RandomField::Path, value })),
            button("Save as…").on_press_maybe((state.can_random() && state.random.picker.is_none()).then_some(Message::RandomBrowse))].spacing(10).align_y(iced::Alignment::End),
        text("Generated bytes are saved only to the requested file. Existing files are never overwritten; a failed operation may leave an empty or partial file.").size(14),
        button("Generate and save").style(button::primary).on_press_maybe(state.can_random().then_some(Message::GenerateRandom)),
        ].spacing(12).into(),
    };
    column![
        button(
            row![
                lucide::arrow_left().size(14),
                text("Back to Operations").size(13)
            ]
            .spacing(8)
        )
        .on_press_maybe(
            state
                .can_submit()
                .then_some(Message::Ui(Action::Task(None)))
        ),
        container(form)
            .padding(20)
            .width(iced::Length::Fill)
            .style(theme::surface)
    ]
    .spacing(24)
    .max_width(720)
    .into()
}
