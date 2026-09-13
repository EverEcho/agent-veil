# AgentVeil Desktop

The desktop shell is a separate Go module so the headless `veil` Core keeps its
CGO-free cross-build and server dependency boundary.

Development compile without a display:

```sh
make desktop-build-ci
```

Native development run (requires the platform packages documented by Fyne):

```sh
go build -o ../veil ../cmd/veil
cd desktop
go run .
```

`agentveil-desktop` expects the `veil` binary beside it. Set
`VEIL_CORE_EXECUTABLE` to an absolute path to override that location. Closing
the window hides it to the system tray. The tray Quit action refuses to exit
while an owned Core still has active protected Sessions.

The first desktop run creates a private `desktop.token` under the AgentVeil user
configuration directory. It is never placed in the autostart entry or process
arguments. `VEIL_ADMIN_TOKEN` can explicitly replace this local adapter in
managed environments.
