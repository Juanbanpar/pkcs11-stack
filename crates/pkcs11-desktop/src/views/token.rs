// SPDX-License-Identifier: MIT OR Apache-2.0
use super::main::field;
use crate::ui::{
    button, checkbox,
    components::{self, EMPHASIS, Tone, badge, muted},
    text_input, theme,
};
use crate::{
    app::Message,
    backend::{LoginRole, LoginState, TokenEntry},
    state::{TokenPage, UiState},
};
use iced::{
    Element, Length,
    widget::{column, container, row, scrollable, text},
};
use iced_fonts::lucide;
use secrecy::ExposeSecret;

pub fn view<'a>(state: &'a UiState, token: &'a TokenEntry) -> Element<'a, Message> {
    let mut tabs = row![].spacing(4);
    for (label, page) in [
        ("Overview", TokenPage::Overview),
        ("Objects", TokenPage::Objects),
        ("Mechanisms", TokenPage::Mechanisms),
        ("Operations", TokenPage::Operations),
        ("Administration", TokenPage::Administration),
    ] {
        tabs = tabs.push(
            button(text(label).size(14))
                .padding([8, 10])
                .arrows()
                .style(if state.token_page == page {
                    theme::selected_tab
                } else {
                    theme::tab
                })
                .on_press_maybe(state.can_submit().then_some(Message::ShowPage(page))),
        );
    }
    let content: Element<'_, Message> = match state.token_page {
        TokenPage::Overview => scrollable(overview(state, token)).spacing(8).into(),
        TokenPage::Objects => objects(state),
        TokenPage::Mechanisms => mechanisms(state),
        TokenPage::Operations => scrollable(super::operations::view(state)).spacing(8).into(),
        TokenPage::Administration => scrollable(super::administration::view(state))
            .spacing(8)
            .into(),
    };
    let module = state.module().expect("selected token has a module");
    let breadcrumbs = row![
        button(text(module.label()).size(12))
            .id("breadcrumb-module")
            .padding([4, 0])
            .style(theme::navigation)
            .on_press(Message::SelectModule(module.id)),
        lucide::chevron_right().size(12).style(theme::muted),
        muted(format!(
            "Token · {}",
            if token.serial.is_empty() {
                "serial unavailable"
            } else {
                &token.serial
            }
        ))
        .size(12),
    ]
    .spacing(8)
    .align_y(iced::Alignment::Center);
    let identity = column![
        text(if token.label.is_empty() {
            "Unnamed token"
        } else {
            &token.label
        })
        .size(24)
        .font(EMPHASIS)
        .wrapping(text::Wrapping::WordOrGlyph),
        muted(format!("{} · {}", token.manufacturer, token.model))
            .size(13)
            .wrapping(text::Wrapping::WordOrGlyph),
    ]
    .spacing(4)
    .width(Length::Fill);
    column![
        breadcrumbs,
        row![identity, authentication(state, token)]
            .spacing(12)
            .align_y(iced::Alignment::Center),
        tabs.wrap(),
        content
    ]
    .spacing(12)
    .height(Length::Fill)
    .into()
}
fn authentication<'a>(state: &'a UiState, token: &'a TokenEntry) -> Element<'a, Message> {
    let enabled = state.can_submit();
    let mut content = row![badge(
        token.login.label(),
        match token.login {
            LoginState::Public => Tone::Neutral,
            LoginState::User => Tone::Success,
            LoginState::SecurityOfficer | LoginState::Unknown => Tone::Warning,
        }
    )]
    .spacing(8)
    .align_y(iced::Alignment::Center);
    if token.login == LoginState::Public {
        content = content
            .push(
                button(text("USER login").size(13)).on_press_maybe(
                    (enabled && token.can_login(LoginRole::User))
                        .then_some(Message::OpenLogin(LoginRole::User)),
                ),
            )
            .push(
                button(text("SO login").size(13)).on_press_maybe(
                    (enabled && token.can_login(LoginRole::SecurityOfficer))
                        .then_some(Message::OpenLogin(LoginRole::SecurityOfficer)),
                ),
            );
    } else {
        content = content.push(
            button(text("Logout").size(13)).on_press_maybe(enabled.then_some(Message::Logout)),
        );
    }
    content.into()
}
pub(super) fn login<'a>(state: &'a UiState, token: &'a TokenEntry) -> Element<'a, Message> {
    let mut content = column![].spacing(12);
    if let Some(form) = &state.login_form {
        let id = form.id;
        content = content.push(
            text(match form.role {
                LoginRole::User => "Login as USER",
                LoginRole::SecurityOfficer => "Login as Security Officer",
            })
            .size(20),
        );
        content = content.push(
            container(
                column![
                    muted("TARGET TOKEN").size(11).font(EMPHASIS),
                    text(if token.label.is_empty() {
                        "Unnamed token"
                    } else {
                        &token.label
                    })
                    .size(16)
                    .font(EMPHASIS),
                    muted(format!("Serial {} · {}", token.serial, token.model)).size(13),
                ]
                .spacing(4),
            )
            .padding(12)
            .width(Length::Fill)
            .style(theme::inset),
        );
        content = content.push(muted(match form.role {
            LoginRole::User => "USER login gives access to private objects on this token.",
            LoginRole::SecurityOfficer => "The Security Officer role can initialize the USER PIN. It is separate from USER login.",
        }));
        if token.protected_path {
            content = content.push(
                checkbox(form.protected_path)
                    .label("Use token's protected authentication path")
                    .on_toggle(move |enabled| Message::ProtectedPath { id, enabled }),
            );
        }
        if form.protected_path {
            content = content.push(text("Complete authentication on the token when prompted."));
        } else {
            content = content.push(
                text_input("PIN", form.pin.expose_secret())
                    .secure(true)
                    .on_input(move |pin| Message::PinInput {
                        id,
                        pin: pin.into(),
                    })
                    .on_submit(Message::SubmitLogin(id)),
            );
        }
        content = content
            .push(
                text("Each submission makes one login attempt. Failed attempts can lock the PIN.")
                    .size(14),
            )
            .push(
                row![
                    button("Login")
                        .style(button::primary)
                        .on_press(Message::SubmitLogin(id)),
                    button("Cancel")
                        .id("modal-cancel")
                        .on_press(Message::DismissLogin(id))
                ]
                .spacing(10),
            );
    }
    content.into()
}

fn overview<'a>(state: &UiState, token: &'a TokenEntry) -> Element<'a, Message> {
    let identity = column![
        field("Manufacturer", &token.manufacturer),
        field("Model", &token.model),
        field("Serial", &token.serial),
        field("Current slot", token.slot_id.to_string())
    ]
    .spacing(12);
    let mut capabilities = column![].spacing(12);
    for (label, value) in &token.details {
        capabilities = capabilities.push(field(
            label,
            match value.as_str() {
                "true" => "Yes",
                "false" => "No",
                _ => value,
            },
        ));
    }
    column![
        text("Identity").size(20),
        container(identity)
            .padding(16)
            .width(Length::Fill)
            .style(crate::ui::theme::surface),
        text("Capabilities and PIN limits").size(20),
        container(capabilities)
            .padding(16)
            .width(Length::Fill)
            .style(crate::ui::theme::surface),
        components::locator(
            state,
            token
                .uri
                .as_deref()
                .unwrap_or("The reported token metadata cannot form a supported locator.")
        ),
    ]
    .spacing(12)
    .into()
}
fn objects(state: &UiState) -> Element<'_, Message> {
    let task = if let Some(form) = &state.crypto_form {
        Some((super::crypto::view(state), Message::DismissCrypto(form.id)))
    } else if let Some(form) = &state.cipher_form {
        Some((super::cipher::view(state), Message::DismissCipher(form.id)))
    } else {
        state.key_form.as_ref().map(|form| {
            (
                super::key_operations::view(state),
                Message::DismissKeyOperation(form.id),
            )
        })
    };
    if let Some((task, back)) = task {
        let mut context = column![
            button("Back to Objects")
                .id("object-task-back")
                .on_press(back)
        ]
        .spacing(12);
        if let Some(object) = state.object() {
            context = context.push(
                container(
                    column![
                        muted("SELECTED OBJECT").size(11).font(EMPHASIS),
                        text(if object.label.is_empty() {
                            "Unnamed object"
                        } else {
                            &object.label
                        })
                        .size(17)
                        .font(EMPHASIS),
                        muted(format!(
                            "{} · ID {}",
                            object.class_name(),
                            object.identifier
                        ))
                        .size(13),
                    ]
                    .spacing(4),
                )
                .padding(12)
                .width(Length::Fill)
                .style(theme::inset),
            );
        }
        return scrollable(context.push(task).max_width(800))
            .spacing(8)
            .into();
    }
    let enabled = state.can_submit();
    let entries = crate::ui::sorted_objects(state);
    let count = entries.len();
    let columns = [
        iced::widget::table::column(
            sort_object(state, "Label", crate::ui::ObjectSort::Label),
            move |object: &crate::backend::ObjectEntry| -> Element<'_, Message> {
                button(
                    text(if object.label.is_empty() {
                        "Unnamed object"
                    } else {
                        &object.label
                    })
                    .wrapping(text::Wrapping::WordOrGlyph),
                )
                .arrows()
                .width(Length::Fill)
                .style(if state.selected_object == Some(object.id) {
                    crate::ui::theme::selected
                } else {
                    crate::ui::theme::navigation
                })
                .on_press_maybe(enabled.then_some(Message::SelectObject(object.id)))
                .into()
            },
        )
        .width(Length::FillPortion(2))
        .align_y(iced::alignment::Vertical::Center),
        iced::widget::table::column(
            sort_object(state, "Class", crate::ui::ObjectSort::Class),
            |object: &crate::backend::ObjectEntry| -> Element<'_, Message> {
                muted(object.class_name()).size(13).into()
            },
        )
        .width(Length::Fill)
        .align_y(iced::alignment::Vertical::Center),
        iced::widget::table::column(
            sort_object(state, "ID", crate::ui::ObjectSort::Identifier),
            |object: &crate::backend::ObjectEntry| -> Element<'_, Message> {
                text(&object.identifier)
                    .font(iced::Font::MONOSPACE)
                    .size(13)
                    .wrapping(text::Wrapping::Glyph)
                    .into()
            },
        )
        .width(Length::Fill)
        .align_y(iced::alignment::Vertical::Center),
    ];
    let mut list = column![
        iced::widget::table(columns, entries)
            .padding(4)
            .separator_x(0)
            .separator_y(1)
    ]
    .spacing(12);
    if count == 0 {
        let (title, description) = if !state.objects_loaded && state.current_operation.is_some() {
            (
                "Reading objects…",
                "The provider is returning the object identities visible to the current role.",
            )
        } else if !state.objects_loaded {
            (
                "Object list unavailable",
                "Use Refresh Objects to retry. The status area shows the last operation result.",
            )
        } else if !state.objects.is_empty() {
            (
                "No matching objects",
                "Try a different label, class, hexadecimal ID or locator.",
            )
        } else if state
            .token()
            .is_some_and(|token| token.login == LoginState::Public)
        {
            (
                "No public objects visible",
                "Log in as USER to see private objects, or refresh after inserting or changing a token.",
            )
        } else {
            (
                "No objects visible",
                "This token has no persistent objects visible to the current role.",
            )
        };
        list = list.push(components::empty(title, description));
        if state.objects_loaded && !state.object_filter.is_empty() {
            list = list.push(button("Clear filter").on_press(Message::ObjectFilter(String::new())));
        }
    }
    let browser = browser(state, list.into(), super::object::detail(state));
    column![
        row![
            text("Objects").size(18).font(EMPHASIS).width(Length::Fill),
            muted(format!("{count} of {} visible", state.objects.len()))
        ]
        .align_y(iced::Alignment::Center),
        text_input("Filter label, class, ID or locator", &state.object_filter)
            .id("object-filter")
            .on_input(Message::ObjectFilter),
        browser,
    ]
    .spacing(10)
    .height(Length::Fill)
    .into()
}

fn sort_object<'a>(
    state: &UiState,
    label: &'a str,
    sort: crate::ui::ObjectSort,
) -> Element<'a, Message> {
    let suffix = if state.presentation.object_sort == sort {
        if state.presentation.object_descending {
            " ↓"
        } else {
            " ↑"
        }
    } else {
        ""
    };
    button(text(format!("{label}{suffix}")).size(14))
        .style(crate::ui::theme::navigation)
        .on_press(Message::Ui(crate::ui::Action::SortObjects(sort)))
        .into()
}

fn mechanisms(state: &UiState) -> Element<'_, Message> {
    let entries = crate::ui::sorted_mechanisms(state);
    let count = entries.len();
    let columns = [
        iced::widget::table::column(
            sort_mechanism(state, "Name", crate::ui::MechanismSort::Name),
            |entry: &crate::backend::MechanismEntry| -> Element<'_, Message> {
                button(
                    text(&entry.name)
                        .font(iced::Font::MONOSPACE)
                        .size(13)
                        .wrapping(text::Wrapping::Glyph),
                )
                .arrows()
                .width(Length::Fill)
                .style(if state.selected_mechanism == Some(entry.id) {
                    crate::ui::theme::selected
                } else {
                    crate::ui::theme::navigation
                })
                .on_press(Message::SelectMechanism(entry.id))
                .into()
            },
        )
        .width(Length::FillPortion(3)),
        iced::widget::table::column(
            sort_mechanism(state, "Identifier", crate::ui::MechanismSort::Identifier),
            |entry: &crate::backend::MechanismEntry| -> Element<'_, Message> {
                text(&entry.identifier)
                    .font(iced::Font::MONOSPACE)
                    .size(14)
                    .into()
            },
        )
        .width(Length::Fill),
    ];
    let mut list = column![
        iced::widget::table(columns, entries)
            .padding(4)
            .separator_x(0)
            .separator_y(1)
    ]
    .spacing(12);
    if count == 0 {
        list = list.push(text(if !state.mechanisms_loaded {
            "Reading mechanisms, or refresh to retry a failed read."
        } else if state.mechanisms.is_empty() {
            "The token advertises no mechanisms."
        } else {
            "No mechanisms match the filter."
        }));
    }
    let mut detail = column![].spacing(12);
    if let Some(entry) = state
        .mechanisms
        .iter()
        .find(|entry| Some(entry.id) == state.selected_mechanism)
    {
        detail = detail
            .push(
                text(&entry.name)
                    .size(18)
                    .font(EMPHASIS)
                    .wrapping(text::Wrapping::Glyph),
            )
            .push(
                column![
                    muted("Identifier").size(12),
                    text(&entry.identifier).size(14).font(iced::Font::MONOSPACE)
                ]
                .spacing(4),
            )
            .push(
                column![
                    muted("Minimum key size").size(12),
                    text(entry.minimum.to_string())
                ]
                .spacing(4),
            )
            .push(
                column![
                    muted("Maximum key size").size(12),
                    text(entry.maximum.to_string())
                ]
                .spacing(4),
            )
            .push(
                text("Bounds are provider values; units and meaning depend on the mechanism.")
                    .size(14),
            )
            .push(text("Advertised flags").size(18));
        if entry.flags.is_empty() {
            detail = detail.push(text("No flags reported."));
        }
        for flag in &entry.flags {
            detail = detail.push(text(*flag));
        }
    } else {
        detail = detail.push(text("Select a mechanism for provider flags and bounds."));
    }
    column![
        row![
            text("Mechanisms")
                .size(18)
                .font(EMPHASIS)
                .width(Length::Fill),
            muted(format!("{count} of {} advertised", state.mechanisms.len()))
        ]
        .align_y(iced::Alignment::Center),
        text_input("Filter name, identifier or flag", &state.mechanism_filter)
            .id("mechanism-filter")
            .on_input(Message::MechanismFilter),
        browser(state, list.into(), detail.into()),
    ]
    .spacing(10)
    .height(Length::Fill)
    .into()
}

fn sort_mechanism<'a>(
    state: &UiState,
    label: &'a str,
    sort: crate::ui::MechanismSort,
) -> Element<'a, Message> {
    let suffix = if state.presentation.mechanism_sort == sort {
        if state.presentation.mechanism_descending {
            " ↓"
        } else {
            " ↑"
        }
    } else {
        ""
    };
    button(text(format!("{label}{suffix}")).size(14))
        .style(crate::ui::theme::navigation)
        .on_press(Message::Ui(crate::ui::Action::SortMechanisms(sort)))
        .into()
}
fn browser<'a>(
    state: &UiState,
    list: Element<'a, Message>,
    detail: Element<'a, Message>,
) -> Element<'a, Message> {
    if state.presentation.width - 252.0 >= 800.0 {
        row![
            container(scrollable(list).spacing(8))
                .padding(8)
                .style(theme::surface)
                .width(Length::FillPortion(3)),
            container(scrollable(detail).spacing(8))
                .padding(16)
                .style(crate::ui::theme::surface)
                .width(Length::FillPortion(2))
        ]
        .spacing(16)
        .height(Length::Fill)
        .into()
    } else if state.presentation.show_detail {
        column![
            button("Back to List").on_press(Message::Ui(crate::ui::Action::BackToList)),
            scrollable(detail).spacing(8)
        ]
        .spacing(12)
        .height(Length::Fill)
        .into()
    } else {
        container(scrollable(list).spacing(8))
            .padding(8)
            .style(theme::surface)
            .height(Length::Fill)
            .into()
    }
}
