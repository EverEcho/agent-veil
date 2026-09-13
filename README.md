# AgentVeil

AgentVeil is a local-first privacy control plane for AI agents. The target
architecture, security invariants, and remaining work are defined in
[`doc/`](doc/README.md); implemented coverage is intentionally reported more
conservatively than discovered traffic.

## Implemented

- domain models for agents, egress surfaces, manifests, routes, plans, sessions,
  findings, policies, networking and audit events;
- a loopback-only Core with capability-authenticated routes, session-revocable
  request processing (including uploads and pending ASK decisions),
  management-authorized per-Session interaction capabilities that default off
  and cannot be escalated by child Sessions,
  version-negotiated management APIs, bounded and strict CLI response envelopes,
  bounded concurrency, failure-wiped capability generation, and safe shutdown;
- protocol-aware request/response rewriting for OpenAI Chat and Responses,
  Anthropic Messages, Gemini, MCP HTTP, and MCP Streamable HTTP; remote MCP
  forwarding preserves the exact configured transport endpoint instead of
  appending the Core's local canonical `/mcp` adapter path; upstream URLs whose
  escaped path cannot be represented losslessly are rejected instead of being
  silently normalized to another endpoint;
- bounded request-header and query DLP with policy-aware value redaction,
  fail-closed sensitive key handling, and explicit Provider-auth exceptions;
  incremental SSE protection with cross-chunk secret detection and placeholder
  restoration; Provider response headers restore only request-local placeholders,
  and blocked header, body, and stream findings contribute metadata-only audit
  records;
- explicit rejection of request or Provider protocol upgrades and implicit
  Cookie/Set-Cookie authentication state;
- deterministic and structured PII/secret detection, chunk caching, layered
  policies, session-stable placeholders, request-scoped bounded Vaults, and a
  shared fail-closed panic boundary for replaceable scanners across request,
  response, stream, audit, rule-test, and diagnostic paths;
- direct, HTTP proxy, system proxy, and SOCKS5 network transports, plus runtime
  Bearer, Anthropic, Google, Vertex, custom, and AWS SigV4 authentication;
- persistent policy and privacy-safe audit stores with retention, plus canonically signed,
  versioned rule-pack and semantic-model artifact stores with rollback; verified
  rule packs can be installed, listed, activated, deactivated, and removed
  through the authenticated management API without exposing a partially switched
  data plane;
- an authenticated local dashboard for discovery, risk-only surface inspection,
  coverage plans, an escaped Routing Graph showing each Surface's protocol,
  policy, fixed Upstream, authentication and network route, nested calls with
  Route/protocol/policy/lifecycle and retained audit summaries, approvals,
  policy editing, local rule tests with rule ID/detector/confidence explanations
  and per-Finding layered policy previews, and
  audit. `ASK` cards offer one-time allow/redact decisions, an original-free
  redaction preview, and an explicit cancel-and-block action. The nested call
  tree also offers a localized, user-confirmed Session revocation control, and
  the Routing Graph can stop an exact Agent registration generation without a
  stale page removing a newer controller.
  Protection risks expose their source
  Surface, severity, impact, and a conservative resolution action; retained
  metadata also drives local-day summaries and a seven-day risk trend, with
  per-response nonce CSP and no inline event handlers. The control surface has
  a semantic main landmark, keyboard skip navigation, visible focus, reduced-
  motion handling, labelled inputs, and polite assistive status announcements.
  Its live Core status distinguishes healthy/degraded API, audit failure counts,
  and required semantic availability. Agent, Session, approval, audit, discovery,
  policy, rule-pack, and model changes made through other local clients converge
  automatically, while an actively edited policy buffer is preserved. A
  browser-language-aware English/Simplified
  Chinese localization layer covers static controls, dynamically inserted
  actions, and parameterized runtime summaries for health, coverage, risks,
  trends, call trees, rule tests, and model resources while persisting only the
  locale preference. A plain-language safety
  guide explains every coverage class, request-scoped sensitive-data lifetime,
  metadata-only retention, and the limits of detection and compliance claims;
  policy and signed-manifest editors preserve the original JSON representation
  so Core can reject duplicate keys instead of accepting a browser-normalized
  interpretation; every Dashboard request and response is explicitly pinned to
  the compiled management API version;
- an authenticated, bounded diagnostics export that omits routes and paths,
  hashes runtime identities, and applies field-level plus final-payload scans,
  available from both CLI and a user-triggered local Dashboard download;
- capability-based coverage planning that cannot label incomplete inspection as
  `Protected`;
- atomic Native/Managed registry reconciliation plus revision-aware monitoring
  backed by bounded, permission-checked, ambiguity-rejecting manifest snapshots
  that block stale protection claims during invalid configuration gaps;
- generation-bound Native integration leases, route capabilities, and heartbeats
  that revoke stale active plans after plugin failure, reconfiguration, or
  disconnect; generation counters are not reused after explicit removal, and
  lease expiry, re-registration, monitoring failure, and explicit removal all
  cascade through matching Session trees to cancel already authorized in-flight
  requests; a bounded revocation backlog fails closed by revoking all Sessions;
- route-capability-authenticated child Session creation that can only reuse the
  authenticated parent Route, cannot outlive its parent or enable interaction,
  shares the existing Core, is revoked by parent-session deletion, and can
  explicitly self-revoke on normal nested-process exit without gaining the
  authority to delete a root or multi-Route Session. Native callers receive the
  authenticated Route protocol and may request a maximum TTL that Core
  atomically narrows to the parent's remaining lifetime;
- manager-level nested Session inheritance that prevents every child creation
  path, including the management API, from switching Core endpoints or adding
  Routes that its parent does not own;
- a strict Go Native Integration SDK in `sdk/native` for trusted host
  controllers to report manifests, renew leases, and remove only their current
  generation, plus a route-capability-only client for creating scoped child
  Sessions without a management token; both accept numeric loopback Core
  endpoints only and contain no DLP implementation. Its bounded lease keeper
  performs health heartbeats, reports every renewed expiry, removes its exact
  generation on shutdown, and fails closed instead of fighting a superseding
  controller through unsafe automatic re-registration;
- a declarative Tool Surface Adapter SDK in `sdk/tooladapter` that enumerates
  Remote MCP and local stdio, forces Browser/OAuth/file/WebSocket/Tool HTTP
  interactions to remain unknown and non-rewritable until Core has a verified
  protocol, and never moves DLP logic into a Native plugin;
- exact upstream allowlisting with HTTPS-by-default, loopback-only HTTP,
  method/path/query-preserving redirect revalidation, and preserved custom
  Gateway base paths; Provider routes neither persist nor replay caller CookieJar
  credentials;
- version-gated Codex, Claude Code, and Hermes discovery/protected launch, plus
  a discovery-only Cursor compatibility record; protected children receive
  only fresh Session/parent/route capabilities and never inherit the Core
  management token;
- bounded Agent configuration inspection restricted to stable regular files,
  with hard deadlines for version commands and inherited output pipes, plus a
  fixed concurrency ceiling for deterministic discovery; temporary Hermes homes
  reject linked, writable, or identity-changing source directories;
- pinned CI actions with race and static analysis, six-target Linux/macOS/Windows
  cross-builds, byte-for-byte reproducible Linux release-build verification,
  an explicit 500-sample pure-rule protocol/detection/policy/redaction P95 gate
  against the documented 15 ms local-path budget,
  time-bounded protocol-body, endpoint-traversal, SSE, exact capability-tuple,
  and Upstream origin-confusion fuzzing, reachable-vulnerability and dependency
  review gates, sensitive-Canary test-log scanning that withholds leaking output,
  and SPDX JSON SBOM generation. Version tags additionally produce six release
  binaries plus checksums, bind them to GitHub/Sigstore build-provenance
  attestations, bind the Linux binary to its SPDX SBOM, and retain the complete
  evidence bundle as an immutable workflow artifact;
- risk-only inspection for unverified Agent versions, which cannot publish a
  rewritable surface or claim protected coverage and includes a required unknown
  Surface whenever the parsed configuration otherwise looks complete; the compatibility inventory
  records verified mode, platform, Surface type, protocol, authentication, and
  coverage independently. Its production validator rejects malformed or duplicate
  records and any Protected claim whose protocol is absent from the same complete
  request/response/stream adapter registry used to configure the runtime Planner.
  Inspection also fails closed when the user configuration directory is
  unavailable or when supported environment overrides contain relative,
  whitespace-ambiguous, oversized, or control-character paths;
- crash-safe Core discovery that atomically persists a random per-process
  identity, removes stale state immediately after claiming the OS instance lock,
  and verifies the unauthenticated identity endpoint before any CLI management
  request can send the administrator token; Hermes Protected Launch resources
  live under a marked private AgentVeil root and residue from the previous Core
  instance is removed only after the new process owns that lock;
- Hermes 0.20.6 enumeration and protected launch for same-runtime
  `openai-codex` primary, fallback, auxiliary, delegation, and remote MCP
  Streamable HTTP surfaces without
  retaining credentials in the manifest; every protected network Surface
  receives an independent Core route and capability in an isolated temporary
  `HERMES_HOME` (model capabilities travel in a stripped loopback path segment,
  while MCP capabilities use stripped headers), including documented
  OpenAI Chat, Responses, and Anthropic api-mode aliases. Runtime `main`, `auto`,
  and legacy custom fallback semantics are expanded before routes are pinned,
  while unsupported specialized transports and legacy MCP SSE remain
  fail-closed and explicitly Unprotected. Legacy SSE now has a bounded,
  exact-capability channel registry for joining GET streams to dynamic Provider
  POST endpoints and destroying shared Vaults on revocation; endpoint-event
  rewriting and the dual-request data path must still be connected before this
  transport can become Protected;
- conservative OpenClaw JSON5 enumeration of model, MCP, ACP, configured Browser,
  and Web Tool surfaces; no OpenClaw release is yet marked as verified or
  protected;
- conservative OpenCode JSONC enumeration of primary/small models and local or
  remote MCP surfaces, with inline, project, and managed override gaps reported
  explicitly; no OpenCode release is yet marked as verified or protected;
- conservative Zed JSONC enumeration of explicit custom model endpoints, local
  and remote MCP servers, and ACP agent processes, while dynamic/keychain and
  project-level routes remain explicit unknown risks;
- conservative Cline CLI enumeration across its provider and MCP stores,
  including legacy SSE versus Streamable HTTP, while IDE-host and workspace
  configuration remain explicit unknown risks;
- conservative Cursor global MCP enumeration, with ambiguous remote transports,
  project/nested MCP, extension registrations, and closed model backends kept as
  explicit unknown risks;
- scoped transparent-mode CA with private atomic activation, local signing
  revocation, restart-reconciled rotation, and a crash-reconciling,
  rollback-capable Linux trust-store file adapter with bounded refresh commands;
  bounded Linux process-tree and TCP/connected-UDP
  egress collection plus fail-closed, serialized process-egress assessment and
  watch primitives. Exact loopback hops are reported as `Local`, never as
  content-protected. Linux protected launches terminate their isolated process
  group after unexpected observed egress or an observation failure and publish
  a route/session/generation-bound, target-free audit event to Core. This is not
  pre-connect blocking and these components are not yet a complete transparent
  interception product or OS enforcement layer.

## Commands

Build or run with Go 1.23 or newer. `serve` requires a random management token
of at least 32 characters:

```bash
export VEIL_ADMIN_TOKEN='replace-with-a-random-32-character-token'
go run ./cmd/veil serve
```

To have Core own and continuously reconcile one Managed/Native integration,
point it at a private, absolute JSON `AgentManifest` file. The initial manifest
must declare `agent.mode` as `managed`; unsafe or invalid initial state prevents
startup, and later invalid revisions immediately block the previous routes until
the file is repaired:

```bash
export VEIL_MANAGED_MANIFEST_PATH='/absolute/path/to/managed-agent.json'
go run ./cmd/veil serve
```

To load an installed signed rule pack, configure its trusted Ed25519 public key
in canonical base64. The store defaults to the private AgentVeil configuration
directory and may be overridden with an absolute path:

```bash
export VEIL_RULE_VERIFY_KEY='base64-ed25519-public-key'
export VEIL_RULE_STORE_PATH='/absolute/path/to/agentveil/rules'
```

An absent active rule version keeps the built-in rules. An invalid active
pointer, signature, digest, JSON document, or compiled rule prevents Core from
starting.

Signed semantic-model artifacts use a separate trust root and private store:

```bash
export VEIL_MODEL_VERIFY_KEY='base64-ed25519-public-key'
export VEIL_MODEL_STORE_PATH='/absolute/path/to/agentveil/models'
```

The authenticated `/v1/models` management API can install, list, activate,
deactivate, and remove verified model artifacts. Activation currently selects
the verified artifact and hot-swaps an injected local semantic runtime only
after loading succeeds; without a configured runtime it does not claim semantic
inference is active. Required semantic detection fails closed while no compatible
active model is loaded. The same local workflow is available in the Dashboard
without loading the full model into JavaScript memory. Core health reports
`required_unavailable` and a degraded status whenever mandatory semantic
inference cannot run. Active runtimes may implement the bounded
`detector.SemanticResourceReporter` contract so `/v1/models` and the Dashboard
show resident bytes, worker count, accelerator, and inference count; unsupported
or failed reporting is shown explicitly instead of estimating model memory from
artifact size.

Rule-test false-positive feedback is retained locally as bounded, validated
metadata in the private AgentVeil configuration directory. It never stores the
test value, match replacement, free-form text, or credentials. Set
`VEIL_FEEDBACK_PATH` to an absolute path to override `feedback.json`.

Other commands discover the active random loopback endpoint from a 0600 local
state file. `VEIL_CORE_ENDPOINT` remains available as an explicit override:

```bash
go run ./cmd/veil status
go run ./cmd/veil agents list
go run ./cmd/veil agents remove codex-local --generation 7
go run ./cmd/veil sessions list
go run ./cmd/veil sessions revoke session-0123456789abcdef0123456789abcdef
go run ./cmd/veil calls
go run ./cmd/veil approvals list
go run ./cmd/veil approvals resolve 0123456789abcdef0123456789abcdef redact
go run ./cmd/veil audit
go run ./cmd/veil compatibility
go run ./cmd/veil compatibility --offline
go run ./cmd/veil diagnostics
go run ./cmd/veil models list
go run ./cmd/veil models install ./signed-model-manifest.json ./model.bin
go run ./cmd/veil models activate 1.0.0
go run ./cmd/veil models deactivate
go run ./cmd/veil models remove 1.0.0
go run ./cmd/veil policy get
go run ./cmd/veil policy apply ./policy.json
go run ./cmd/veil rules list
go run ./cmd/veil rules install ./signed-manifest.json ./rules.json
go run ./cmd/veil rules activate 1.0.0
go run ./cmd/veil rules deactivate
go run ./cmd/veil rules remove 1.0.0
go run ./cmd/veil discover
go run ./cmd/veil inspect codex
go run ./cmd/veil inspect claude
go run ./cmd/veil inspect hermes
go run ./cmd/veil inspect openclaw
go run ./cmd/veil inspect opencode
go run ./cmd/veil inspect zed
go run ./cmd/veil inspect cline
go run ./cmd/veil inspect cursor
go run ./cmd/veil run codex -- --help
go run ./cmd/veil run codex --interactive -- exec "review this change"
go run ./cmd/veil run hermes -- --help
go run ./cmd/veil nested codex -- exec "review delegated work"
```

`veil status` validates and reports Core API, audit persistence, and semantic
runtime health separately, including retained audit failure counts when Core is
degraded. CLI management requests never follow redirects.
`veil agents`, `veil sessions`, and `veil calls` expose the same bounded live
registration, Session, and nested call-tree facts used by the Dashboard without
returning management or Route capabilities. Call-tree structure is revalidated
before it is printed. `veil sessions revoke` explicitly tears down the selected
root or child Session after validating its fixed capability-safe identifier.
`veil agents remove` requires the displayed generation, so a stale controller
cannot remove a newer registration with the same Agent ID.

The offline compatibility form reads the same validated matrix compiled into
the binary and needs neither a running Core nor a management token. Tagged CI
builds include that exact `COMPATIBILITY.json` in checksums and provenance.
Rule commands use the authenticated, versioned loopback management API. Install
accepts only bounded regular files, rejects symlinks and ambiguous manifest
JSON, and leaves signature verification and atomic activation to Core.
Model commands use the same local management boundary. Model installation streams
the bounded regular artifact from disk, checks its size against the strict signed
manifest, and leaves signature and digest verification to Core.
Policy commands retrieve or atomically apply the same document used by the
Dashboard. Apply rejects symlinks, oversized or ambiguous JSON, unknown fields,
invalid actions, malformed scopes, and duplicate scopes before contacting Core.
Interactive launches can be approved from either the Dashboard or
`veil approvals`: the CLI lists metadata-only Findings and accepts one-time
`allow`, `redact`, or `block` decisions. Non-interactive `ASK` remains fail-closed.
`veil audit` returns only the bounded recent metadata retained by Core and
revalidates every event against the privacy-safe audit contract before printing.

`veil nested` is intended for a process already launched inside an AgentVeil
Route context. It uses only the inherited `VEIL_CORE_ENDPOINT`,
`VEIL_SESSION_ID`, `VEIL_ROUTE_ID`, and `VEIL_PROTECTION_TOKEN`, creates a
non-interactive child Session on that exact Route, reuses the existing Core,
and revokes the child Session on exit. Nested Codex uses standard capability
Headers, including on Hermes Routes that additionally support path capabilities,
so Route Tokens never enter child argv; nested Claude requires a verified
Anthropic API-key capability Route. No Core management token is inherited or
required.

Protected Claude launch currently requires `ANTHROPIC_API_KEY`. OAuth-only
Claude launch remains unverified and fails closed. Hermes protected launch is
version-gated to 0.20.6 and the verified same-runtime `openai-codex` route set;
every discovered network Surface must be rewritable, so another provider or an
unknown route blocks the whole launch. CLI protected launches
create non-interactive Sessions by default, so an `ASK` policy blocks instead
of waiting indefinitely. Pass `--interactive` before the argument separator to
opt into one-time decisions through the Dashboard.

## Verification

Run the tests with:

```bash
go test -race ./...
go vet ./...
```

The hardware-sensitive pure-rule core-path P95 acceptance gate is opt-in for
local runs and mandatory in CI:

```bash
VEIL_PERFORMANCE_GATE=1 go test ./internal/pipeline -run '^TestPureRulePipelineP95Budget$' -count=1 -v
```

The repository is still under active development. Native/managed integrations,
complete desktop UX, production transparent MITM and OS enforcement, local
semantic-model distribution, signed installers, release publication, and the
formal release process remain open.
