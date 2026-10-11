// SPDX-License-Identifier: GPL-3.0-or-later
//! Native desktop application over the synchronous client library.
mod app;
mod backend;
mod state;
mod views;

fn main() -> iced::Result {
    iced::application(app::App::boot, app::App::update, app::App::view)
        .title("PKCS#11 Desktop")
        .window_size((1060.0, 720.0))
        .theme(app::App::theme)
        .subscription(app::App::subscription)
        .exit_on_close_request(false)
        .run()
}
