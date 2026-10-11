# pkcs11-desktop

Native Iced window with welcome and module navigation pages, light/dark themes,
status messages and a synthetic background operation. It uses `pkcs11-client` as
its application API; module loading and token browsing are not implemented yet.

## Development

Rust 1.88 or newer. Iced 0.14 uses `tiny-skia`, `thread-pool`, `x11` and `wayland`,
with default features disabled.

```sh
cargo run -p pkcs11-desktop --locked
cargo test -p pkcs11-desktop --locked
```

Linux build dependencies on Ubuntu:

```sh
sudo apt-get install pkg-config libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libx11-dev libxcursor-dev libxrandr-dev libxi-dev libegl1-mesa-dev
```

## Execution

One worker thread processes a bounded command queue. Iced receives results through
a subscription. The synthetic operation waits 350 ms, then returns success or a
fixed error, allowing responsiveness and error handling to be tested without a token.

Request IDs associate results with the active operation. Cancellation, navigation
or another request invalidates an earlier result; it does not interrupt worker
execution. A full queue returns an error without blocking the UI. Closing the
window stops submissions, drains queued work and joins the worker off the UI thread.

`app.rs` routes messages and tasks, `state.rs` holds UI state, `views/` builds the
layout, and `backend.rs` owns the worker. Message Debug omits payloads; commands
have no Debug implementation. Errors use fixed presentation text. UI state holds
no PINs, session handles or object handles.

## License

This application is licensed under [GPL-3.0-or-later](COPYING).
