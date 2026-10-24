// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{Action, button, theme};
use crate::{app::Message, state::UiState};
use iced::{
    Element, Font, Length,
    widget::{Text, column, container, row, text},
};
use iced_fonts::lucide;

pub const EMPHASIS: Font = Font {
    weight: iced::font::Weight::Semibold,
    ..Font::DEFAULT
};

pub fn muted<'a>(content: impl text::IntoFragment<'a>) -> Text<'a> {
    text(content).size(14).style(theme::muted)
}

#[derive(Clone, Copy)]
pub enum Tone {
    Neutral,
    Info,
    Success,
    Warning,
}

pub fn badge<'a>(label: impl text::IntoFragment<'a>, tone: Tone) -> Element<'a, Message> {
    iced_aw::Badge::new(text(label).size(12).font(EMPHASIS))
        .padding(5)
        .style(move |theme: &iced::Theme, _| {
            let palette = theme.extended_palette();
            let pair = match tone {
                Tone::Neutral => palette.background.strong,
                Tone::Info => palette.primary.weak,
                Tone::Success => palette.success.weak,
                Tone::Warning => palette.warning.weak,
            };
            iced_aw::style::badge::Style {
                background: pair.color.into(),
                text_color: pair.text,
                border_radius: Some(6.0),
                border_width: 0.0,
                border_color: None,
            }
        })
        .into()
}

pub fn notice<'a>(title: &'a str, description: &'a str) -> Element<'a, Message> {
    container(
        row![
            lucide::info().size(18),
            column![text(title).size(14).font(EMPHASIS), muted(description)].spacing(4)
        ]
        .spacing(10),
    )
    .padding(12)
    .width(Length::Fill)
    .style(theme::notice)
    .into()
}

pub fn task_card<'a>(
    icon: Text<'a>,
    title: &'a str,
    description: &'a str,
    requirement: &'a str,
    message: Option<Message>,
) -> Element<'a, Message> {
    button(
        row![
            icon.size(22).style(theme::accent),
            column![
                row![
                    text(title).size(16).font(EMPHASIS).width(Length::Fill),
                    muted(requirement).size(12)
                ]
                .spacing(10)
                .align_y(iced::Alignment::Center),
                muted(description),
            ]
            .spacing(6)
            .width(Length::Fill),
            lucide::chevron_right().size(16).style(theme::muted)
        ]
        .spacing(14)
        .align_y(iced::Alignment::Center),
    )
    .padding(14)
    .width(Length::Fill)
    .style(theme::task_card)
    .on_press_maybe(message)
    .into()
}

pub fn locator<'a>(state: &UiState, value: &'a str) -> Element<'a, Message> {
    let expanded = state.presentation.locator_expanded;
    let icon = if expanded {
        lucide::chevron_down()
    } else {
        lucide::chevron_right()
    };
    let mut content = column![
        button(
            row![
                icon.size(14),
                text(if expanded {
                    "Hide PKCS#11 locator"
                } else {
                    "Show PKCS#11 locator"
                })
                .size(13)
            ]
            .spacing(6)
        )
        .padding([6, 0])
        .style(theme::navigation)
        .on_press(Message::Ui(Action::ToggleLocator))
    ]
    .spacing(6);
    if expanded {
        content = content.push(
            container(
                text(value)
                    .size(13)
                    .font(Font::MONOSPACE)
                    .wrapping(text::Wrapping::Glyph),
            )
            .padding(12)
            .width(Length::Fill)
            .style(theme::inset),
        );
    }
    content.into()
}

pub fn empty<'a>(title: &'a str, explanation: &'a str) -> Element<'a, Message> {
    container(
        column![
            lucide::inbox().size(28).style(theme::muted),
            text(title).size(18).font(EMPHASIS),
            muted(explanation)
        ]
        .spacing(10),
    )
    .padding(24)
    .width(Length::Fill)
    .style(theme::surface)
    .into()
}
