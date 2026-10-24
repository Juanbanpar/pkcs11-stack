// SPDX-License-Identifier: MIT OR Apache-2.0
use iced::{
    Background, Border, Color, Theme,
    widget::{button, container},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Appearance {
    #[default]
    System,
    Light,
    Dark,
}

pub fn theme(dark: bool) -> Theme {
    let palette = if dark {
        iced::theme::Palette {
            background: Color::from_rgb8(36, 36, 36),
            text: Color::from_rgb8(246, 245, 244),
            primary: Color::from_rgb8(120, 174, 237),
            warning: Color::from_rgb8(249, 240, 107),
            success: Color::from_rgb8(143, 240, 164),
            danger: Color::from_rgb8(255, 123, 99),
        }
    } else {
        iced::theme::Palette {
            background: Color::from_rgb8(246, 245, 244),
            text: Color::from_rgb8(36, 36, 36),
            primary: Color::from_rgb8(28, 113, 216),
            warning: Color::from_rgb8(156, 110, 3),
            success: Color::from_rgb8(27, 133, 83),
            danger: Color::from_rgb8(192, 28, 40),
        }
    };
    Theme::custom_with_fn(
        if dark {
            "Desktop Dark"
        } else {
            "Desktop Light"
        },
        palette,
        move |palette| {
            use iced::theme::palette::{Background, Extended, Pair};
            let mut extended = Extended::generate(palette);
            let pair = |gray| Pair::new(Color::from_rgb8(gray, gray, gray), palette.text);
            extended.background = if dark {
                Background {
                    base: pair(36),
                    weakest: pair(40),
                    weaker: pair(44),
                    weak: pair(48),
                    neutral: pair(52),
                    strong: pair(64),
                    stronger: pair(78),
                    strongest: pair(92),
                }
            } else {
                Background {
                    base: pair(250),
                    weakest: pair(246),
                    weaker: pair(242),
                    weak: pair(238),
                    neutral: pair(232),
                    strong: pair(218),
                    stronger: pair(202),
                    strongest: pair(186),
                }
            };
            extended
        },
    )
}

pub fn surface(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(p.background.weak.color.into()),
        border: Border {
            radius: 8.0.into(),
            width: 1.0,
            color: p.background.strong.color,
        },
        ..Default::default()
    }
}
pub fn sidebar(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(theme.extended_palette().background.weak.color.into()),
        ..Default::default()
    }
}
pub fn shade(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.35).into()),
        ..Default::default()
    }
}
pub fn error(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(p.danger.weak.color.into()),
        text_color: Some(p.danger.weak.text),
        border: Border {
            radius: 8.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}
pub fn secondary(theme: &Theme, status: button::Status) -> button::Style {
    let p = theme.extended_palette();
    let background = match status {
        button::Status::Hovered => p.background.strong.color,
        button::Status::Pressed => p.background.weak.color,
        _ => p.background.base.color,
    };
    button::Style {
        background: Some(Background::Color(background)),
        text_color: p
            .background
            .base
            .text
            .scale_alpha(if status == button::Status::Disabled {
                0.45
            } else {
                1.0
            }),
        border: Border {
            radius: 8.0.into(),
            width: 1.0,
            color: p.background.strong.color,
        },
        ..Default::default()
    }
}
pub fn navigation(theme: &Theme, status: button::Status) -> button::Style {
    let mut style = secondary(theme, status);
    style.border.width = 0.0;
    if status == button::Status::Active {
        style.background = None;
    }
    style
}
pub fn selected(theme: &Theme, status: button::Status) -> button::Style {
    let p = theme.extended_palette();
    let mut style = secondary(theme, status);
    style.background = Some(p.primary.weak.color.into());
    style.text_color = p.primary.weak.text;
    style.border.width = 0.0;
    style
}
pub fn primary(theme: &Theme, status: button::Status) -> button::Style {
    let mut style = button::primary(theme, status);
    style.border.radius = 8.0.into();
    style
}
pub fn danger(theme: &Theme, status: button::Status) -> button::Style {
    let mut style = button::danger(theme, status);
    style.border.radius = 8.0.into();
    style
}
