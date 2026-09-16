# AgentVeil Desktop

AgentVeil Desktop is a Tauri 2 shell built from the same Dashboard source that
`veil serve` embeds for browser clients. CLI-only installations open the
Core-served copy in a browser; desktop installations load the bundled copy
locally inside the native Tauri window.

The Rust shell owns desktop-only concerns: safe Core adoption/startup,
close-to-tray behavior, guarded shutdown, single instance, sign-in startup, and
signed updates for the selected `dev`, `beta`, or `release` channel.
The local page reaches the versioned Core API through a bounded Rust command
bridge. The bridge owns the management token and exposes only the Dashboard's
explicit method/path allowlist, so the token is never injected into JavaScript.
Opening the browser Dashboard from the tray first mints a 30-second one-time
ticket. The page immediately removes it from the URL and exchanges it for a
same-origin, HttpOnly browser-session cookie; there is no manual token form.

The crate keeps those boundaries explicit: `core_supervisor.rs` owns the Core
process, `bridge.rs` owns the authenticated API contract, `tray.rs` owns native
desktop controls, `updater.rs` owns update settings and state, and `main.rs` is
only composition and shutdown wiring.

## Development

Install Rust 1.88 or newer and the platform prerequisites from the Tauri
documentation, then run:

```sh
cd desktop
cargo tauri dev
```

Set `VEIL_CORE_EXECUTABLE` to an absolute Core binary when `veil` is not next
to the desktop executable. Release workflows place Core in
`src-tauri/resources/` before bundling.
