# pkcs11-desktop

Native PKCS#11 module and token browser built with Iced and `pkcs11-client`.
Load trusted vendor libraries, inspect module and slot metadata, and view token
identity, initialization, authentication flags and PIN limits. Browse public
objects and advertised mechanisms with local filters and metadata details.

## Usage

Choose a module with **Browse**, or enter its file path, then select **Load**.
The sidebar lists loaded modules and their tokens. Select a module for library and
slot information, or a token for its overview and locator.

**Refresh module** re-enumerates the selected module's slots and tokens. Removed or
replaced tokens clear their selection. **Unload** finalizes the selected module;
quitting finalizes all loaded modules.

Select **Objects** to list persistent objects visible without login. Filter by
label, class, hexadecimal ID or locator, then select an object to read its metadata.
Listing requests only class, label and ID; detail reads use a small metadata
allowlist and never fetch object values or private key material. Missing,
sensitive and unsupported attributes remain distinguishable. Objects with
duplicate locators or unsupported identities show their summary without a detail
read. **Refresh objects** clears selection and reads a new list.

Select **Mechanisms** to browse provider-advertised names, identifiers, flags and
key-size bounds. Filter by name, hexadecimal identifier or flag, and use
**Refresh mechanisms** to re-enumerate. Bounds retain the provider's units;
the browser does not plan or execute cryptographic operations.

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
refresh, inspection and finalization. Object browsing uses scoped read-only
sessions without authentication and reports explicit close failures. The UI
receives metadata snapshots and local resource IDs, without providers, sessions
or raw handles. An unchanged token keeps its ID
across module refreshes; a replacement receives a new ID. Object IDs last for one
list snapshot. Details resolve their client locator again in a fresh session.

Request IDs reject cancelled or superseded results. Refresh cancellation ignores
its eventual result. Token/page/object changes invalidate pending reads. Load and
unload complete before another lifecycle command can start; navigation remains
available. Closing the window drains queued work,
finalizes providers and joins the worker off the UI thread.

Tests cover state transitions, stale responses, picker results, backend errors,
shutdown, lazy details, ambiguous objects, metadata redaction and isolated SoftHSM
module/object/mechanism workflows:

```sh
PKCS11_TEST_DESKTOP=1 ./tools/test-softhsm.sh
```

## License

This application is licensed under [GPL-3.0-or-later](COPYING).
