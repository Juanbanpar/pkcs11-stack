// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    app::Message,
    backend::AdministrationKind,
    state::{AdministrationField, AdministrationPinField, UiState},
};
use iced::{
    Element,
    widget::{button, column, container, text, text_input},
};
use secrecy::ExposeSecret;
pub fn view(state: &UiState) -> Element<'_, Message> {
    let mut content = column![text("Token and PIN administration").size(22), text("These actions change persistent token state. Host PINs are required; protected-path administration is unsupported. PIN changes end this app's login on the selected token. Each submission makes one attempt; incorrect credentials may lock the PIN.").size(14), column![button("Initialize / erase token…").on_press_maybe(state.can_administer(AdministrationKind::InitializeToken).then_some(Message::OpenAdministration(AdministrationKind::InitializeToken))), button("Initialize / reset USER PIN…").on_press_maybe(state.can_administer(AdministrationKind::InitializeUserPin).then_some(Message::OpenAdministration(AdministrationKind::InitializeUserPin))), button("Change current role's PIN…").on_press_maybe(state.can_administer(AdministrationKind::ChangePin).then_some(Message::OpenAdministration(AdministrationKind::ChangePin)))].spacing(10), text("USER PIN initialization requires SO login. Change PIN uses the logged-in USER or SO role. Token initialization uses the current SO PIN on an initialized token, or sets the SO PIN on an uninitialized token.").size(14)].spacing(12);
    let Some(form) = &state.administration_form else {
        return content.into();
    };
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
        fields = fields.push(text(format!("Advertised PIN byte bounds: {}–{}. The provider may impose further restrictions.", bound(form.expected.minimum_pin_length), bound(form.expected.maximum_pin_length))).size(14)).push(button("Review change…").on_press(Message::ReviewAdministration(id)));
    }
    fields = fields.push(button("Cancel").on_press(Message::DismissAdministration(id)));
    content = content.push(container(fields).padding(12).style(container::rounded_box));
    content.into()
}

fn bound(value: usize) -> String {
    if value == usize::MAX {
        "unspecified".into()
    } else {
        value.to_string()
    }
}
