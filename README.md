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
  version-negotiated management APIs, bounded concurrency, and safe shutdown;
- protocol-aware request/response rewriting for OpenAI Chat and Responses,
  Anthropic Messages, Gemini, MCP HTTP, and MCP Streamable HTTP;
- incremental SSE protection with cross-chunk secret detection and placeholder
  restoration;
- deterministic and structured PII/secret detection, chunk caching, layered
  policies, session-stable placeholders, and request-scoped bounded Vaults;
- direct, HTTP proxy, system proxy, and SOCKS5 network transports, plus runtime
  Bearer, Anthropic, Google, Vertex, custom, and AWS SigV4 authentication;
- persistent policy and privacy-safe audit stores with retention, plus signed,
  versioned rule-pack and semantic-model artifact stores with rollback; verified
  rule packs can be installed, listed, activated, deactivated, and removed
  through the authenticated management API without exposing a partially switched
  data plane;
- an authenticated local dashboard for discovery, risk-only surface inspection,
  coverage plans, nested calls, approvals, policy editing, rule tests, and audit;
- an authenticated, bounded diagnostics export that omits routes and paths,
  hashes runtime identities, and applies field-level plus final-payload scans;
- capability-based coverage planning that cannot label incomplete inspection as
  `Protected`;
- atomic Native/Managed registry reconciliation plus revision-aware monitoring
  that blocks stale protection claims during invalid configuration gaps;
- generation-bound Native integration leases, route capabilities, and heartbeats
  that revoke stale active plans after plugin failure, reconfiguration, or
  disconnect;
- exact upstream allowlisting with HTTPS-by-default, loopback-only HTTP,
  method/path/query-preserving redirect revalidation, and preserved custom
  Gateway base paths;
- version-gated Codex and Claude Code discovery/protected launch, plus
  discovery-only Hermes and Cursor compatibility records; protected children
  receive route capabilities but never inherit the Core management token;
- risk-only inspection for unverified Agent versions, which cannot publish a
  rewritable surface or claim protected coverage;
- Hermes 0.20.6 enumeration of primary, fallback, auxiliary, delegation, and MCP
  surfaces without retaining credentials;
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
  revocation, restart-reconciled rotation, and a rollback-capable Linux
  trust-store file adapter; bounded Linux process-tree and TCP/connected-UDP
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

Other commands discover the active random loopback endpoint from a 0600 local
state file. `VEIL_CORE_ENDPOINT` remains available as an explicit override:

```bash
go run ./cmd/veil status
go run ./cmd/veil diagnostics
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
```

Protected Claude launch currently requires `ANTHROPIC_API_KEY`. OAuth-only
Claude and Hermes protected launch remain unverified and fail closed.

## Verification

Run the tests with:

```bash
go test -race ./...
go vet ./...
```

The repository is still under active development. Native/managed integrations,
complete desktop UX, production transparent MITM and OS enforcement, local
semantic-model distribution, and release/supply-chain hardening remain open.
