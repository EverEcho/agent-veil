# AgentVeil Desktop

AgentVeil Desktop is a Tauri 2 shell around the same Dashboard served by
`veil serve`. CLI-only installations open it in a browser; desktop
installations render it inside the native Tauri window.

The Rust shell owns desktop-only concerns: safe Core adoption/startup,
close-to-tray behavior, guarded shutdown, single instance, and sign-in startup.

## Development

Install the platform prerequisites from the Tauri documentation, then run:

```sh
cd desktop
cargo tauri dev
```

Set `VEIL_CORE_EXECUTABLE` to an absolute Core binary when `veil` is not next
to the desktop executable. Release workflows place Core in
`src-tauri/resources/` before bundling.
