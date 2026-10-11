// SPDX-License-Identifier: GPL-3.0-or-later
use super::main::field;
use crate::{
    app::Message,
    backend::{MetadataField, TokenEntry},
    state::{TokenPage, UiState},
};
use iced::{
    Element, Length,
    widget::{button, column, container, row, rule, scrollable, text, text_input},
};

pub fn view<'a>(state: &'a UiState, token: &'a TokenEntry) -> Element<'a, Message> {
    let mut tabs = row![].spacing(10);
    for (label, page) in [
        ("Overview", TokenPage::Overview),
        ("Objects", TokenPage::Objects),
        ("Mechanisms", TokenPage::Mechanisms),
    ] {
        tabs = tabs.push(
            button(label)
                .style(if state.token_page == page {
                    button::primary
                } else {
                    button::secondary
                })
                .on_press_maybe(state.can_submit().then_some(Message::ShowPage(page))),
        );
    }
    let content = match state.token_page {
        TokenPage::Overview => overview(token),
        TokenPage::Objects => objects(state),
        TokenPage::Mechanisms => mechanisms(state),
    };
    column![
        text(if token.label.is_empty() {
            "Unnamed token"
        } else {
            &token.label
        })
        .size(30),
        tabs,
        content
    ]
    .spacing(18)
    .into()
}
fn overview(token: &TokenEntry) -> Element<'_, Message> {
    let mut content = column![
        field("Manufacturer", &token.manufacturer),
        field("Model", &token.model),
        field("Serial", &token.serial),
        field("Current slot", token.slot_id.to_string())
    ]
    .spacing(12);
    for (label, value) in &token.details {
        content = content.push(field(label, value));
    }
    content
        .push(text("Token locator").size(20))
        .push(text(token.uri.as_deref().unwrap_or(
            "The reported token metadata cannot form a supported locator.",
        )))
        .into()
}
fn metadata(fields: &[MetadataField]) -> Element<'_, Message> {
    let mut content = column![].spacing(10);
    for entry in fields {
        let value = entry
            .value
            .as_deref()
            .map(|value| if value.is_empty() { "(empty)" } else { value })
            .unwrap_or(entry.status);
        content = content.push(field(entry.name, value));
    }
    content.into()
}
fn objects(state: &UiState) -> Element<'_, Message> {
    let enabled = state.can_submit();
    let mut list = column![].spacing(8);
    let mut count = 0;
    for object in state
        .objects
        .iter()
        .filter(|entry| entry.matches(&state.object_filter))
    {
        count += 1;
        let label = if object.label.is_empty() {
            "Unnamed object"
        } else {
            &object.label
        };
        list = list.push(
            button(
                column![
                    text(label),
                    text(format!(
                        "{} · ID {}",
                        object.class_name(),
                        if object.identifier.is_empty() {
                            "—"
                        } else {
                            &object.identifier
                        }
                    ))
                    .size(13)
                ]
                .spacing(4),
            )
            .width(Length::Fill)
            .style(if state.selected_object == Some(object.id) {
                button::primary
            } else {
                button::secondary
            })
            .on_press_maybe(enabled.then_some(Message::SelectObject(object.id))),
        );
    }
    if count == 0 {
        list = list.push(text(if !state.objects_loaded {
            "Object list has not been read. Refresh to retry."
        } else if state.objects.is_empty() {
            "No persistent objects are visible without login."
        } else {
            "No objects match the filter."
        }));
    }
    let mut detail = column![].spacing(12);
    if let Some(object) = state.object() {
        detail = detail
            .push(text("Object metadata").size(20))
            .push(metadata(&object.fields));
        if let Some(uri) = &object.uri {
            detail = detail.push(text("Object locator").size(18)).push(text(uri));
        } else {
            detail = detail.push(text(
                "The available identity attributes cannot form a supported object locator.",
            ));
        }
        if object.ambiguous {
            detail = detail.push(text(
                "Several listed objects share this locator; details cannot be selected uniquely.",
            ));
        } else if let Some(fields) = &state.object_details {
            detail = detail.push(rule::horizontal(1)).push(metadata(fields));
        } else if object.uri.is_some() {
            detail = detail.push(text(
                "Details are read on selection. Select again to retry a failed or cancelled read.",
            ));
        }
    } else {
        detail = detail.push(text("Select an object to read its metadata."));
    }
    column![
        row![
            text_input("Filter label, class, ID or locator", &state.object_filter)
                .on_input(Message::ObjectFilter),
            button("Refresh objects").on_press_maybe(enabled.then_some(Message::RefreshObjects))
        ]
        .spacing(10),
        text(format!(
            "{count} of {} objects · public persistent objects only",
            state.objects.len()
        ))
        .size(14),
        row![
            container(scrollable(list).height(340)).width(Length::FillPortion(2)),
            container(detail).width(Length::FillPortion(3)).padding(12)
        ]
        .spacing(16)
    ]
    .spacing(14)
    .into()
}
fn mechanisms(state: &UiState) -> Element<'_, Message> {
    let mut list = column![].spacing(8);
    let mut count = 0;
    for entry in state
        .mechanisms
        .iter()
        .filter(|entry| entry.matches(&state.mechanism_filter))
    {
        count += 1;
        list = list.push(
            button(column![text(&entry.name), text(&entry.identifier).size(13)])
                .width(Length::Fill)
                .style(if state.selected_mechanism == Some(entry.id) {
                    button::primary
                } else {
                    button::secondary
                })
                .on_press(Message::SelectMechanism(entry.id)),
        );
    }
    if count == 0 {
        list = list.push(text(if !state.mechanisms_loaded {
            "Mechanism list has not been read. Refresh to retry."
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
            .push(text(&entry.name).size(20))
            .push(field("Identifier", &entry.identifier))
            .push(field("Minimum key size", entry.minimum.to_string()))
            .push(field("Maximum key size", entry.maximum.to_string()))
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
            text_input("Filter name, identifier or flag", &state.mechanism_filter)
                .on_input(Message::MechanismFilter),
            button("Refresh mechanisms")
                .on_press_maybe(state.can_submit().then_some(Message::RefreshMechanisms))
        ]
        .spacing(10),
        text(format!("{count} of {} mechanisms", state.mechanisms.len())).size(14),
        row![
            container(scrollable(list).height(340)).width(Length::FillPortion(2)),
            container(detail).width(Length::FillPortion(3)).padding(12)
        ]
        .spacing(16)
    ]
    .spacing(14)
    .into()
}
