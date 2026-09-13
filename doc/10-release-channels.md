# Release channels

AgentVeil uses three ordered release channels. A package's channel describes its
evidence level; it is not only a version suffix.

| Branch | Channel | Required quality |
| --- | --- | --- |
| `dev` | Development | Known nonfatal bugs are allowed. Fatal bugs are not. |
| `beta` | Beta | No known bugs after feature self-test. Wider use may still reveal bugs. |
| `main` | Stable | Fully usable, all shipped functionality confirmed, and no known bugs. |

Promotion is one way: `dev` to `beta` to `main`. Code is merged forward only
after the target channel's quality statement is true. A successful build does
not by itself promote a revision or prove that the statement is true.

## Packaging

The `Package release channel` workflow automatically creates a development
artifact after a push to `dev`. It can also be run manually from GitHub Actions:

1. Select **Package release channel** and choose **Run workflow**.
2. Select the branch matching the requested channel.
3. Enter a version and select the exact quality statement for that channel.
4. Leave **publish_release** off to create only a downloadable workflow
   artifact, or enable it to create a GitHub Release. Development and beta
   GitHub Releases are marked as prereleases.

The workflow rejects branch/channel mismatches. Development runs use a short
compile, vet, and critical-package test gate. Beta runs execute the full test
suite and acceptance evidence. Main runs additionally use the race detector.
All channels package six headless Core targets, a Linux amd64 desktop shell,
and self-contained macOS desktop app bundles for Intel and Apple Silicon, plus
compatibility metadata, channel metadata, and SHA-256 checksums. Each macOS app
contains its matching Core executable beside the desktop executable.

The development and beta macOS apps are ad-hoc signed. A main release still
requires Apple Developer ID signing, notarization, and platform acceptance
evidence. Native Windows desktop packaging also remains pending.
