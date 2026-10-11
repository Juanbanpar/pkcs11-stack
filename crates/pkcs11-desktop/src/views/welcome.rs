// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{app::Message, backend::SyntheticOutcome, state::UiState};
use iced::{
    Element,
    widget::{button, column, row, text},
};

pub fn view(state: &UiState) -> Element<'_, Message> {
    let enabled = state.worker_available && state.shutdown_request.is_none();
    column![
        text("Welcome").size(30),
        text("PKCS#11 Desktop").size(20),
        text("The desktop shell is ready. Module and token browsing comes next."),
        text("Try a synthetic operation to check the background worker. You can switch pages or change theme while it runs."),
        row![
            button("Test worker").on_press_maybe(enabled.then_some(Message::Run(SyntheticOutcome::Success))),
            button("Test error").on_press_maybe(enabled.then_some(Message::Run(SyntheticOutcome::Failure))),
            button("Cancel result").on_press_maybe(state.current_operation.map(|_| Message::Cancel)),
        ].spacing(10),
    ].spacing(18).into()
}
