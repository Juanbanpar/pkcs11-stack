// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::ui::{button, components::EMPHASIS, pick_list, text_input};
use crate::{
    app::Message,
    backend::{CryptoMode, KeyProfile},
    state::{EcdhChoice, HkdfOutputChoice, KeyField, UiState},
};
use iced::{
    Element,
    widget::{column, container, row, text},
};
pub fn view(state: &UiState) -> Element<'_, Message> {
    let Some(form) = &state.key_form else {
        return column![].into();
    };
    if matches!(
        form.scope.mode,
        CryptoMode::Hmac | CryptoMode::VerifyHmac | CryptoMode::Mac | CryptoMode::VerifyMac
    ) {
        return super::mac::view(state);
    }
    if form.scope.mode == CryptoMode::Kbkdf {
        return super::kbkdf::view(state);
    }
    if form.scope.mode == CryptoMode::Hkdf {
        return super::hkdf::view(state);
    }
    let id = form.id;
    let enabled = state.can_submit();
    let wrap = form.scope.mode == CryptoMode::Wrap;
    let derive = form.scope.mode == CryptoMode::Derive;
    let encapsulate = form.scope.mode == CryptoMode::Encapsulate;
    let decapsulate = form.scope.mode == CryptoMode::Decapsulate;
    let kem = encapsulate || decapsulate;
    let title = if encapsulate {
        "Encapsulate an ML-KEM shared secret"
    } else if decapsulate {
        "Decapsulate an ML-KEM shared secret"
    } else if derive {
        "Derive an ECDH shared secret"
    } else if wrap {
        "Wrap an AES key"
    } else {
        "Unwrap an AES key"
    };
    let mut content = column![text(title).size(22).font(EMPHASIS)].spacing(10);
    if let Some(profile) = form.profile {
        content = content.push(text(match profile {
            KeyProfile::Classical(pkcs11_client::KeyOperationProfile::EcdhRaw(curve)) => format!("ECDH {curve:?}. Select the KDF and output purpose explicitly. Parameter support is checked by the token when deriving; a rejected KDF is never replaced. Authenticate the peer public key separately."),
            KeyProfile::AesWrapping(caps) => format!("AES-{} wrapping key. Select KW or KWP explicitly; decryption requires the same algorithm. The blob contains no label, ID or permissions. Only AES-128/192/256 targets and outputs are supported.", caps.key_length * 8),
            KeyProfile::Classical(_) => "No compatible key-operation profile.".into(),
            KeyProfile::Kbkdf(_) | KeyProfile::Hmac(_) | KeyProfile::AesCmac(_) | KeyProfile::Hkdf(_) => "No compatible key-operation profile.".into(),
            KeyProfile::MlKem(parameter) => format!("ML-KEM-{}: {}-byte raw ciphertext. The 32-byte shared secret stays on the token; apply a protocol KDF before use and authenticate the peer separately.", match parameter { pkcs11_client::MlKemParameterSet::MlKem512 => 512, pkcs11_client::MlKemParameterSet::MlKem768 => 768, pkcs11_client::MlKemParameterSet::MlKem1024 => 1024 }, parameter.ciphertext_length()),
        }).size(14));
    } else {
        content = content.push(text(if form.loaded {
            "This key has no permitted profile for this operation."
        } else {
            "Reading permitted key operation profile…"
        }));
    }
    if let Some(KeyProfile::AesWrapping(caps)) = form.profile {
        let algorithms: Vec<_> = [
            pkcs11_client::AesKeyWrapAlgorithm::Kw,
            pkcs11_client::AesKeyWrapAlgorithm::Kwp,
        ]
        .into_iter()
        .filter(|a| caps.supports(*a))
        .collect();
        content = content.push(
            pick_list(algorithms, Some(form.wrap_algorithm), move |algorithm| {
                Message::WrapAlgorithm { id, algorithm }
            })
            .placeholder("Wrapping algorithm")
            .enabled(enabled),
        );
    }
    if derive {
        content = content.push(
            pick_list(EcdhChoice::ALL, Some(form.ecdh.kdf), move |kdf| {
                Message::EcdhKdf { id, kdf }
            })
            .enabled(enabled),
        );
        if form.ecdh.kdf != EcdhChoice::Raw {
            content = content
                .push(
                    pick_list(
                        HkdfOutputChoice::ALL,
                        Some(form.ecdh.output),
                        move |output| Message::EcdhOutput { id, output },
                    )
                    .enabled(enabled),
                )
                .push(
                    text_input("Public shared info (UTF-8, optional)", &form.ecdh.info)
                        .on_input_maybe(enabled.then_some(move |value| Message::KeyEdit {
                            id,
                            field: KeyField::Info,
                            value,
                        })),
                );
            if form.ecdh.output == HkdfOutputChoice::DerivationSecret {
                content = content.push(
                    text_input("Output length in bytes (1–4096)", &form.ecdh.length)
                        .on_input_maybe(enabled.then_some(move |value| Message::KeyEdit {
                            id,
                            field: KeyField::Length,
                            value,
                        })),
                );
            }
        } else {
            content = content.push(text("Raw output preserves the full shared secret, including all 66 bytes on P-521. It needs a protocol KDF before cryptographic use.").size(14));
        }
    }
    if wrap {
        content = content.push(pick_list(form.targets.clone(), form.target.clone(), move |target| Message::KeyTarget { id, target }).placeholder("Target secret key").enabled(enabled))
            .push(text("The target must be an extractable AES key that satisfies the wrapping trust policy. This action does not change key permissions.").size(14));
    } else {
        if !encapsulate {
            content = content.push(
                row![
                    text_input(
                        if decapsulate {
                            "ML-KEM ciphertext input file (raw bytes)"
                        } else if derive {
                            "Peer public key file (SPKI DER)"
                        } else {
                            "Wrapped AES input file (24/32/40 bytes)"
                        },
                        &form.input
                    )
                    .on_input_maybe(enabled.then_some(move |value| {
                        Message::KeyEdit {
                            id,
                            field: KeyField::Input,
                            value,
                        }
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
        }
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
        content = content.push(text(if kem || (derive && (form.ecdh.kdf == EcdhChoice::Raw || form.ecdh.output == HkdfOutputChoice::DerivationSecret)) { "Creates a persistent sensitive, nonextractable generic secret with derivation permission only. No encryption, decryption, signing or wrapping is allowed. Existing secret key IDs are rejected. Failure may leave an object; refresh before retrying." } else { "Creates a persistent private sensitive, nonextractable AES key with encryption/decryption permission only. Existing secret key IDs are rejected. Failure may leave an object; refresh before retrying." }).size(14));
    }
    if decapsulate {
        content = content.push(text("ML-KEM implicit rejection can accept altered ciphertext of the correct length and create a different secret. Completion does not confirm that peers share the same secret. Always-authenticate decapsulation keys are unsupported.").size(14));
    }
    if wrap || encapsulate {
        content = content.push(row![text_input(if encapsulate { "New ML-KEM ciphertext output file" } else { "New wrapped output file" }, &form.output).on_input_maybe(enabled.then_some(move |value| Message::KeyEdit { id, field: KeyField::Output, value })), button("Save as…").on_press_maybe((enabled && form.picker.is_none()).then_some(Message::KeyBrowse { id, field: KeyField::Output }))].spacing(10).align_y(iced::Alignment::End))
            .push(text(if encapsulate { "Only public ciphertext is written. A token secret may already exist if output or cleanup fails. Existing files are never overwritten; failure may leave an empty or partial file. Refresh before retrying." } else { "Existing files are never overwritten. Failure may leave an empty or partial output file." }).size(14));
    }
    content = content.push(
        row![
            button(if encapsulate {
                "Encapsulate once"
            } else if decapsulate {
                "Decapsulate once"
            } else if derive {
                "Derive once"
            } else if wrap {
                "Wrap once"
            } else {
                "Unwrap once"
            })
            .style(button::primary)
            .on_press_maybe(
                (enabled
                    && form
                        .profile
                        .is_some_and(|profile| profile.supports(form.scope.mode)))
                .then_some(Message::SubmitKeyOperation(id))
            ),
            button("Cancel").on_press(Message::DismissKeyOperation(id))
        ]
        .spacing(10)
        .align_y(iced::Alignment::End),
    );
    container(content)
        .padding(18)
        .style(crate::ui::theme::surface)
        .into()
}
