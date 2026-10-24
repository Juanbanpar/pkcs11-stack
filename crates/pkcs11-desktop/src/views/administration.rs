// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::ui::{
    button,
    components::{self, EMPHASIS, muted},
    text_input,
};
use crate::{
    app::Message,
    backend::AdministrationKind,
    state::{AdministrationField, AdministrationPinField, UiState},
};
use iced::{
    Element,
    widget::{column, container, text},
};
use iced_fonts::lucide;
use secrecy::ExposeSecret;
pub fn view(state: &UiState) -> Element<'_, Message> {
    let Some(form) = &state.administration_form else {
        let common = if state.token().is_some_and(|token| token.protected_path) {
            "Protected path unsupported"
        } else if state.token().is_some_and(|token| token.write_protected) {
            "Read-only token"
        } else {
            "Host PIN required"
        };
        return column![
            text("Administration").size(20).font(EMPHASIS),
            muted("Change token initialization or credentials. Every change requires a review and explicit confirmation."),
            components::task_card(lucide::shield(), "Initialize / erase token…", "Initialize a new token, or permanently erase an existing token's objects and reset its USER PIN.", common, state.can_administer(AdministrationKind::InitializeToken).then_some(Message::OpenAdministration(AdministrationKind::InitializeToken))),
            components::task_card(lucide::key(), "Initialize / reset USER PIN…", "Set a USER PIN through the Security Officer role. This ends the token's login in this app.", "SO login required", state.can_administer(AdministrationKind::InitializeUserPin).then_some(Message::OpenAdministration(AdministrationKind::InitializeUserPin))),
            components::task_card(lucide::lock(), "Change current role's PIN…", "Change the credential for the logged-in USER or SO role using its current PIN.", "USER or SO required", state.can_administer(AdministrationKind::ChangePin).then_some(Message::OpenAdministration(AdministrationKind::ChangePin))),
            components::notice("One attempt per submission", "An incorrect credential can lock a PIN. Administration is not retried automatically, and a failed provider call may still apply changes."),
        ].spacing(12).max_width(850).into();
    };
    let mut content = column![].spacing(16);
    let id = form.id;
    let mut fields = column![
        text(match form.kind {
            AdministrationKind::InitializeToken => "Initialize / erase selected token",
            AdministrationKind::InitializeUserPin => "Initialize / reset USER PIN",
            AdministrationKind::ChangePin => "Change authenticated role's PIN",
        })
        .size(20)
    ]
    .spacing(10);
    if form.reviewing {
        let module = state.module().unwrap();
        fields = fields.push(text(format!(
            "Module: {}\nSlot: {}\nToken: {}\nSerial: {}\nRole: {}",
            module.path.display(),
            form.expected.slot_id,
            form.expected.label,
            form.expected.serial,
            form.role.label()
        )));
        fields = fields.push(text(if form.kind == AdministrationKind::InitializeToken { "This erases all objects and resets the USER PIN. All of this app's sessions for this module will close, including other tokens. Ensure exclusive access to the physical token. Type ERASE to confirm." } else { "This changes the selected credential and closes this app's login on this token. A failed call may still apply the change. Type CHANGE to confirm." }));
        if form.kind == AdministrationKind::InitializeToken {
            fields = fields.push(text(format!("New token label: {}", form.label)));
        }
        fields = fields
            .push(
                text_input("Confirmation", &form.confirmation).on_input(move |value| {
                    Message::AdministrationEdit {
                        id,
                        field: AdministrationField::Confirmation,
                        value,
                    }
                }),
            )
            .push(
                button(if form.kind == AdministrationKind::InitializeToken {
                    "Erase and initialize token"
                } else {
                    "Apply PIN change"
                })
                .style(button::danger)
                .on_press(Message::SubmitAdministration(id)),
            );
    } else {
        if form.kind == AdministrationKind::ChangePin
            || (form.kind == AdministrationKind::InitializeToken && form.expected.initialized)
        {
            fields = fields.push(
                text_input(
                    if form.kind == AdministrationKind::InitializeToken {
                        "Current SO PIN"
                    } else {
                        "Current role's PIN"
                    },
                    form.old_pin.expose_secret(),
                )
                .secure(true)
                .on_input(move |pin| Message::AdministrationPin {
                    id,
                    field: AdministrationPinField::Current,
                    pin: pin.into(),
                }),
            );
        }
        if form.kind != AdministrationKind::InitializeToken || !form.expected.initialized {
            fields = fields
                .push(
                    text_input(
                        if form.kind == AdministrationKind::InitializeToken {
                            "New SO PIN"
                        } else {
                            "New PIN"
                        },
                        form.new_pin.expose_secret(),
                    )
                    .secure(true)
                    .on_input(move |pin| Message::AdministrationPin {
                        id,
                        field: AdministrationPinField::New,
                        pin: pin.into(),
                    }),
                )
                .push(
                    text_input("Confirm new PIN", form.confirm_pin.expose_secret())
                        .secure(true)
                        .on_input(move |pin| Message::AdministrationPin {
                            id,
                            field: AdministrationPinField::Confirm,
                            pin: pin.into(),
                        }),
                );
        }
        if form.kind == AdministrationKind::InitializeToken {
            fields = fields.push(
                text_input("New token label (1–32 UTF-8 bytes)", &form.label).on_input(
                    move |value| Message::AdministrationEdit {
                        id,
                        field: AdministrationField::Label,
                        value,
                    },
                ),
            );
        }
        fields = fields.push(text(format!("Advertised PIN byte bounds: {}–{}. The provider may impose further restrictions.", bound(form.expected.minimum_pin_length), bound(form.expected.maximum_pin_length))).size(14)).push(button("Review change…").style(button::primary).on_press(Message::ReviewAdministration(id)));
    }
    fields = fields.push(button("Cancel").on_press(Message::DismissAdministration(id)));
    content = content.push(
        container(fields)
            .padding(12)
            .style(crate::ui::theme::surface),
    );
    content.into()
}

fn bound(value: usize) -> String {
    if value == usize::MAX {
        "unspecified".into()
    } else {
        value.to_string()
    }
}
