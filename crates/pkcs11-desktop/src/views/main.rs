// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::ui::{
    button,
    components::{self, EMPHASIS, muted},
    text_input,
};
use crate::{
    app::Message,
    backend::ModuleEntry,
    state::{Dialog, Notification, Screen, UiState},
    ui::{Action, Overlay, inert, theme},
    views::{token, welcome},
};
use iced::{
    Element, Length,
    widget::{column, container, row, rule, scrollable, text},
};
use iced_fonts::lucide;

pub fn module_form(state: &UiState) -> Element<'_, Message> {
    let enabled = state.can_submit();
    column![
        row![
            text_input("Module file", &state.module_path)
                .id("module-path")
                .on_input_maybe(enabled.then_some(Message::EditPath))
                .on_submit_maybe(
                    (enabled && !state.module_path.is_empty()).then_some(Message::Load)
                ),
            button("Browse…").on_press_maybe(
                (enabled && state.picker_request.is_none()).then_some(Message::Browse)
            ),
            button("Load").style(button::primary).on_press_maybe(
                (enabled && !state.module_path.is_empty()).then_some(Message::Load)
            ),
        ]
        .spacing(10)
        .align_y(iced::Alignment::End),
        text("Loading executes the selected library. Use a module from a trusted provider.")
            .size(14),
    ]
    .spacing(8)
    .into()
}
pub(super) fn field<'a>(label: &'a str, value: impl Into<String>) -> Element<'a, Message> {
    row![
        text(label).size(14).width(140),
        text(value.into())
            .width(Length::Fill)
            .wrapping(text::Wrapping::WordOrGlyph)
    ]
    .spacing(12)
    .into()
}
fn module_view<'a>(state: &'a UiState, module: &'a ModuleEntry) -> Element<'a, Message> {
    let mut overview = column![
        muted("PROVIDER MODULE").size(11).font(EMPHASIS),
        text(module.label())
            .size(26)
            .font(EMPHASIS)
            .wrapping(text::Wrapping::WordOrGlyph),
        muted(&module.description),
        container(
            column![
                field("Library file", module.path.to_string_lossy().into_owned()),
                field("Manufacturer", &module.manufacturer),
                field("Library version", &module.library_version),
                field("PKCS#11 version", &module.cryptoki_version)
            ]
            .spacing(12)
        )
        .padding(16)
        .width(Length::Fill)
        .style(theme::surface),
        text(format!("Tokens ({})", module.tokens.len()))
            .size(18)
            .font(EMPHASIS),
    ]
    .spacing(14);
    for token in &module.tokens {
        overview = overview.push(
            button(
                row![
                    lucide::key().size(19).style(theme::accent),
                    column![
                        text(if token.label.is_empty() {
                            "Unnamed token"
                        } else {
                            &token.label
                        })
                        .size(16)
                        .font(EMPHASIS),
                        muted(format!("{} · {}", token.model, token.serial)).size(13)
                    ]
                    .spacing(4)
                    .width(Length::Fill),
                    components::badge(token.login.label(), components::Tone::Neutral),
                    lucide::chevron_right().size(16)
                ]
                .spacing(12)
                .align_y(iced::Alignment::Center),
            )
            .width(Length::Fill)
            .padding(16)
            .style(theme::task_card)
            .id(format!("module-token-{:?}", token.id))
            .on_press(Message::SelectToken {
                module: module.id,
                token: token.id,
            }),
        );
    }
    if let Some(error) = module.discovery_error {
        overview = overview
            .push(text(error.message()))
            .push(text("Refresh to retry discovery, or unload the module."));
    } else if module.slots.is_empty() {
        overview = overview.push(text("The module reports no slots."));
    }
    overview = overview.push(
        text(format!("Slots ({})", module.slots.len()))
            .size(18)
            .font(EMPHASIS),
    );
    for slot in &module.slots {
        overview = overview.push(
            container(
                column![
                    text(format!("Slot {} · {}", slot.id, slot.description)),
                    text(format!(
                        "{} · {}",
                        slot.manufacturer,
                        if slot.token_present {
                            "token present"
                        } else {
                            "no token present"
                        }
                    )),
                ]
                .spacing(6),
            )
            .padding(12)
            .style(crate::ui::theme::surface),
        );
    }
    if module.tokens.is_empty() && module.discovery_error.is_none() {
        overview = overview.push(text("No tokens available. Insert a token and refresh."));
    }
    overview
        .push(
            button("Unload Module")
                .style(theme::destructive_quiet)
                .on_press_maybe(state.can_submit().then_some(Message::Unload)),
        )
        .into()
}

pub fn view(state: &UiState) -> Element<'_, Message> {
    let refresh_label = match (state.token().is_some(), state.token_page) {
        (true, crate::state::TokenPage::Objects) => "Refresh Objects",
        (true, crate::state::TokenPage::Mechanisms) => "Refresh Mechanisms",
        _ => "Refresh",
    };
    let toolbar = container(
        row![
            row![
                lucide::shield().size(21).style(theme::accent),
                text("PKCS#11 Desktop").size(16).font(EMPHASIS)
            ]
            .spacing(10)
            .align_y(iced::Alignment::Center)
            .width(Length::Fill),
            button(
                row![lucide::plus().size(16), text("Add Module…").size(14)]
                    .spacing(6)
                    .align_y(iced::Alignment::Center)
            )
            .id("add-module")
            .on_press_maybe(state.can_submit().then_some(Message::Ui(Action::AddModule))),
            button(
                row![lucide::rotate_cw().size(15), text(refresh_label).size(14)]
                    .spacing(6)
                    .align_y(iced::Alignment::Center)
            )
            .on_press_maybe(
                (state.module().is_some() && state.can_submit())
                    .then_some(Message::Ui(Action::Refresh))
            ),
            button(text("Appearance").size(14))
                .style(theme::navigation)
                .id("appearance")
                .on_press(Message::Ui(Action::Appearance)),
            button(text("Help").size(14))
                .style(theme::navigation)
                .id("keyboard-help")
                .on_press(Message::Ui(Action::KeyboardHelp)),
            button(text("About").size(14))
                .style(theme::navigation)
                .on_press(Message::About),
        ]
        .spacing(6)
        .align_y(iced::Alignment::Center),
    )
    .padding([10, 16]);
    let mut navigation = column![
        muted("WORKSPACE").size(11).font(EMPHASIS),
        button(
            row![lucide::house().size(16), text("Welcome").size(14)]
                .spacing(10)
                .align_y(iced::Alignment::Center)
        )
        .width(Length::Fill)
        .style(if state.screen == Screen::Welcome {
            theme::selected
        } else {
            theme::navigation
        })
        .arrows()
        .on_press(Message::Navigate(Screen::Welcome)),
        button(
            row![lucide::database().size(16), text("Modules").size(14)]
                .spacing(10)
                .align_y(iced::Alignment::Center)
        )
        .width(Length::Fill)
        .style(
            if state.screen == Screen::Modules && state.selected_module.is_none() {
                theme::selected
            } else {
                theme::navigation
            }
        )
        .arrows()
        .on_press(Message::Navigate(Screen::Modules)),
    ]
    .spacing(4);
    navigation = navigation.push(
        container(
            row![
                muted("LOADED MODULES")
                    .size(11)
                    .font(EMPHASIS)
                    .width(Length::Fill),
                components::badge(
                    state.loaded_modules.len().to_string(),
                    components::Tone::Neutral
                )
            ]
            .align_y(iced::Alignment::Center),
        )
        .padding([16, 0]),
    );
    if state.loaded_modules.is_empty() {
        navigation = navigation.push(muted("Add a module to see its tokens here."));
    }
    for module in &state.loaded_modules {
        let collapsed = state.presentation.collapsed.contains(&module.id.0);
        navigation = navigation.push(
            row![
                button(if collapsed {
                    lucide::chevron_right().size(14)
                } else {
                    lucide::chevron_down().size(14)
                })
                .padding([8, 6])
                .style(theme::navigation)
                .on_press(Message::Ui(Action::ToggleModule(module.id))),
                button(
                    text(module.label())
                        .size(13)
                        .font(EMPHASIS)
                        .wrapping(text::Wrapping::WordOrGlyph)
                )
                .width(Length::Fill)
                .arrows()
                .style(
                    if state.selected_module == Some(module.id) && state.selected_token.is_none() {
                        theme::selected
                    } else {
                        theme::navigation
                    }
                )
                .on_press(Message::SelectModule(module.id)),
            ]
            .spacing(4),
        );
        if !collapsed {
            for token in &module.tokens {
                let label = if token.label.is_empty() {
                    "Unnamed token"
                } else {
                    &token.label
                };
                navigation = navigation.push(
                    container(
                        button(
                            column![
                                text(label).size(14).wrapping(text::Wrapping::WordOrGlyph),
                                muted(&token.serial).size(12)
                            ]
                            .spacing(4),
                        )
                        .width(Length::Fill)
                        .arrows()
                        .style(if state.selected_token == Some(token.id) {
                            theme::selected
                        } else {
                            theme::navigation
                        })
                        .on_press(Message::SelectToken {
                            module: module.id,
                            token: token.id,
                        }),
                    )
                    .padding([0, 12]),
                );
            }
        }
    }
    let content: Element<'_, Message> = match state.screen {
        Screen::Welcome => scrollable(welcome::view(state)).spacing(8).into(),
        Screen::Modules => {
            if let Some(token) = state.token() {
                token::view(state, token)
            } else if let Some(module) = state.module() {
                scrollable(module_view(state, module)).spacing(8).into()
            } else {
                scrollable(
                    column![
                        text("Modules").size(28),
                        text("Load a module or select one from the sidebar."),
                        button("Add Module…")
                            .id("modules-add-module")
                            .style(button::primary)
                            .on_press_maybe(
                                state.can_submit().then_some(Message::Ui(Action::AddModule))
                            )
                    ]
                    .spacing(24),
                )
                .spacing(8)
                .into()
            }
        }
    };
    let body = row![
        container(scrollable(navigation).spacing(8))
            .width(212)
            .height(Length::Fill)
            .padding(12)
            .style(theme::sidebar),
        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .padding([18, 20]),
    ]
    .height(Length::Fill);
    let mut layout = column![toolbar, rule::horizontal(1)];
    if let Some(Notification::Error(error)) = state.notification {
        layout = layout.push(
            container(
                row![
                    text(error.message()).width(Length::Fill),
                    button("Dismiss").on_press(Message::DismissNotification)
                ]
                .spacing(12),
            )
            .padding(12)
            .width(Length::Fill)
            .style(theme::error),
        );
    }
    layout = layout.push(body);
    let status_text = match state.notification {
        Some(Notification::Error(_)) | None => state.status().to_owned(),
        Some(Notification::RandomSaved(length)) => {
            format!("{length} token random bytes saved to the requested file.")
        }
        Some(notification) if state.current_operation.is_none() => notification.text().to_owned(),
        _ => state.status().to_owned(),
    };
    let mut status = row![].spacing(12).align_y(iced::Alignment::Center);
    if state.current_operation.is_some() || state.shutdown_request.is_some() {
        status = status.push(iced_aw::Spinner::new().width(16).height(16));
    }
    status = status.push(text(status_text).size(14).width(Length::Fill));
    if state.can_cancel() {
        status = status.push(button("Discard Result").on_press(Message::Cancel));
    }
    layout = layout
        .push(rule::horizontal(1))
        .push(container(status).padding([8, 16]));
    let base = container(layout)
        .width(Length::Fill)
        .height(Length::Fill)
        .into();
    let content = if let Some(dialog) = dialog(state) {
        iced::widget::stack![
            inert(base),
            container(
                container(scrollable(dialog).spacing(8))
                    .padding(24)
                    .max_width(640)
                    .max_height(560)
                    .style(theme::surface)
            )
            .center(Length::Fill)
            .style(theme::shade)
        ]
        .into()
    } else {
        base
    };
    crate::ui::root(content)
}

fn dialog(state: &UiState) -> Option<Element<'_, Message>> {
    let close = || {
        button("Close")
            .id("overlay-close")
            .on_press(Message::Ui(Action::Close))
    };
    let content: Element<'_, Message> = if let Some(choice) = &state.presentation.choice {
        let mut choices = column![text(&choice.title).size(22)].spacing(8);
        for (index, (label, message)) in choice.options.iter().enumerate() {
            choices = choices.push(
                button(text(label))
                    .width(Length::Fill)
                    .arrows()
                    .id(if index == 0 {
                        "choice-first".to_owned()
                    } else if index + 1 == choice.options.len() {
                        "choice-last".to_owned()
                    } else {
                        format!("choice-{index}")
                    })
                    .on_press(Message::Ui(Action::Choose(Box::new(message.clone())))),
            );
        }
        choices.push(close()).into()
    } else if let Some(overlay) = state.presentation.overlay {
        match overlay {
            Overlay::AddModule => column![text("Add Module").size(24), module_form(state), close().id("modal-cancel")].spacing(16).into(),
            Overlay::Appearance => {
                use crate::ui::theme::Appearance;
                let mut content = column![text("Appearance").size(24), text("Choose the window's light or dark style.")].spacing(12);
                for (label, appearance) in [("Follow System", Appearance::System), ("Light", Appearance::Light), ("Dark", Appearance::Dark)] {
                    content = content.push(button(label).style(if state.presentation.appearance == appearance { theme::selected } else { theme::navigation }).on_press(Message::Ui(Action::SetAppearance(appearance))));
                }
                content.push(close()).into()
            }
            Overlay::KeyboardHelp => column![text("Keyboard Shortcuts").size(24), text("Tab / Shift+Tab — move between controls\nArrow keys — navigate lists and choices\nEnter / Space — activate the focused control\nEscape — close the current dialog or form\nCtrl+O — add a module\nCtrl+F — focus the resource filter\nCtrl+R — refresh the current resource\nCtrl+Q — close the application\n\nUse Command instead of Ctrl on macOS."), close(), button("Quit").on_press(Message::CloseRequested)].spacing(16).into(),
        }
    } else if state.login_form.is_some() {
        token::login(state, state.token()?)
    } else if let Some(Dialog::Delete(id)) = state.dialog {
        let object = state.object()?;
        column![
            text("Delete Object?").size(24),
            text(
                "This permanently deletes this object only; related keys and certificates are kept."
            ),
            container(
                column![
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
                    )),
                    muted(
                        state
                            .token()
                            .map(|token| format!("Token {} · {}", token.label, token.serial))
                            .unwrap_or_default()
                    ),
                ]
                .spacing(6)
            )
            .padding(12)
            .width(Length::Fill)
            .style(theme::inset),
            text(object.uri.as_deref().unwrap_or(""))
                .size(13)
                .font(iced::Font::MONOSPACE)
                .wrapping(text::Wrapping::Glyph),
            row![
                button("Cancel")
                    .id("modal-cancel")
                    .on_press(Message::DismissDialog),
                button("Delete Permanently")
                    .style(button::danger)
                    .on_press(Message::ConfirmDelete(id))
            ]
            .spacing(12)
        ]
        .spacing(16)
        .into()
    } else if state.dialog == Some(Dialog::About) {
        column![text("PKCS#11 Desktop").size(24).font(EMPHASIS), text("Browse tokens, manage objects, and perform cryptographic operations through PKCS#11 modules."), muted("MIT OR Apache-2.0"), button("Close").id("modal-cancel").on_press(Message::DismissDialog), text("Icon notices").size(16).font(EMPHASIS), text(include_str!("../../LICENSE-LUCIDE")).size(12)].spacing(16).into()
    } else {
        return None;
    };
    Some(
        if let Some(Notification::Error(error)) = state.notification {
            column![
                content,
                container(text(error.message()))
                    .padding(12)
                    .style(theme::error)
            ]
            .spacing(12)
            .into()
        } else {
            content
        },
    )
}
