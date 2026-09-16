# Release channels and updates

AgentVeil uses one long-lived Git branch, `main`, and three release channels.
Choose the channel manually when packaging. New code enters `main` through a
pull request; the chosen channel describes the quality of that package.

| Channel | Required quality |
| --- | --- |
| `dev` | Known nonfatal bugs are allowed. Fatal bugs are not. |
| `beta` | No known bugs after feature self-test. Wider use may still reveal bugs. |
| `release` | Fully usable, all shipped functionality confirmed, and no known bugs. |

The same `main` commit can be packaged for any channel when it meets that
channel's quality requirement. Versions are numeric SemVer and increase globally
across all channels; the same numeric version must not be published in more than
one channel.

To package from GitHub Actions, run **Package release channel** manually, select
the `main` branch, then choose `dev`, `beta`, or `release` and its matching quality
statement. Set `publish_release` only when the artifacts should also be published
as a GitHub Release. A dev package can ship after a targeted fix without waiting
for beta or release quality, but it must still have no fatal bugs.

## In-app updates

Desktop users can select `dev`, `beta`, or `release` in Settings. The selection
is stored locally and defaults to the channel used to build the installed app.
AgentVeil checks that exact channel at startup and never downgrades. Download and
installation each require explicit confirmation. Tauri verifies every update
with the dedicated updater public key before installation.

In-app installation supports macOS Intel/Apple Silicon, Windows x64, and Linux
x64 AppImage. Debian packages remain a manual update path because an installed
`.deb` requires the system package manager. The normal installers remain on the
versioned GitHub Release; each channel also has a stable, machine-readable
`latest.json` release.

Updater signing is separate from Apple notarization and Windows code signing.
GitHub Actions requires `TAURI_SIGNING_PRIVATE_KEY` and
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. A release build also fails closed without
the documented Apple distribution credentials.

## Local release command

On macOS or Linux, preview the next version based on locally known tags without
changing anything. Publish mode fetches remote tags before resolving an omitted
version:

```bash
./release.sh --channel dev
```

Pass `--version X.Y.Z` to choose an explicit version. Add `--publish` only when
ready. Publishing requires a clean checkout on `main`, fetches the remote branch
and tags, verifies local HEAD exactly matches `origin/main`, then dispatches
`package-channel.yml` with the immutable commit SHA:

```bash
./release.sh --channel beta --version 0.2.0 --publish
./release.sh --channel release --version 1.0.0 --publish
```

`release.sh` uses `gh workflow run` to start **Package release channel**. After
the packages pass their channel gate, the workflow publishes the GitHub Release
and its version tag, then starts the tag's CI release evidence run. Ordinary
CI runs for pull requests into `main`; merging does not repeat that suite.

The workflow requires `main` and validates the selected channel's quality
statement and numeric version. Dev
uses the short critical-package gate, beta runs the complete suite and
acceptance evidence, and release additionally runs the race detector. It builds
six Core targets plus Linux x64, Windows x64, macOS Intel, and macOS Apple
Silicon desktop bundles. Published dev/beta versions are prereleases; release
uses the plain `vX.Y.Z` tag.

Apple distribution and notarization use `APPLE_CERTIFICATE`,
`APPLE_CERTIFICATE_PASSWORD`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`, and
optionally `APPLE_SIGNING_IDENTITY`. Development and beta macOS packages may use
ad-hoc signing when these are absent; release may not.
