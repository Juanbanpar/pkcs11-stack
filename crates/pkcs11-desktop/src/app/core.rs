// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    backend::{EventSource, Worker},
    state::{Notification, UiState},
    views,
};
use iced::{Element, Subscription, Theme};

use super::Message;

pub struct App {
    pub state: UiState,
    pub(super) worker: Option<Worker>,
    source: Option<EventSource>,
}
impl App {
    #[cfg(test)]
    pub(crate) fn without_worker(state: UiState) -> Self {
        Self {
            state,
            worker: None,
            source: None,
        }
    }

    pub fn boot() -> Self {
        let mut state = UiState::default();
        let (worker, source) = match Worker::spawn() {
            Ok((worker, source)) => {
                state.worker_available = true;
                (Some(worker), Some(source))
            }
            Err(error) => {
                state.notification = Some(Notification::Error(error));
                (None, None)
            }
        };
        Self {
            state,
            worker,
            source,
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let events = self
            .source
            .as_ref()
            .map_or_else(Subscription::none, |source| {
                Subscription::run_with(source.clone(), EventSource::stream).map(Message::Backend)
            });
        Subscription::batch([
            events,
            iced::system::theme_changes()
                .map(|mode| Message::Ui(crate::ui::Action::SystemTheme(mode))),
            iced::window::resize_events()
                .map(|(_, size)| Message::Ui(crate::ui::Action::Resize(size))),
            iced::window::close_requests().map(|_| Message::CloseRequested),
        ])
    }

    pub fn theme(&self) -> Theme {
        crate::ui::theme::theme(self.state.presentation.dark())
    }

    pub fn view(&self) -> Element<'_, Message> {
        views::main::view(&self.state)
    }
}
