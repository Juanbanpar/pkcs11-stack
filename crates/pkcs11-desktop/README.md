# pkcs11-desktop

Native PKCS#11 module and token browser built with Iced and `pkcs11-client`.
Load trusted vendor libraries, inspect module and slot metadata, and view token
identity, initialization, authentication flags and PIN limits.

## Usage

Choose a module with **Browse**, or enter its file path, then select **Load**.
The sidebar lists loaded modules and their tokens. Select a module for library and
slot information, or a token for its overview and locator.

**Refresh** re-enumerates the selected module's slots and tokens. Removed or
replaced tokens clear their selection. **Unload** finalizes the selected module;
quitting finalizes all loaded modules. Browsing does not authenticate or open sessions.

On Linux, the native file picker uses the desktop portal, with a Zenity fallback.
Manual path entry also works when no picker service is available. Modules are
loaded only after an explicit Load action; paths are not saved or loaded on startup.

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

One worker owns all client providers and performs module loading, discovery,
refresh and finalization. The UI receives metadata snapshots and local resource
IDs, without providers, sessions or raw handles. An unchanged token keeps its ID
across refreshes; a replacement receives a new ID.

Request IDs reject cancelled or superseded results. Refresh cancellation ignores
its eventual result. Load and unload complete before another lifecycle command
can start; navigation remains available. Closing the window drains queued work,
finalizes providers and joins the worker off the UI thread.

Tests cover state transitions, stale responses, picker results, backend errors,
shutdown and an isolated SoftHSM load/refresh/unload cycle:

```sh
PKCS11_TEST_DESKTOP=1 ./tools/test-softhsm.sh
```

## License

This application is licensed under [GPL-3.0-or-later](COPYING).
