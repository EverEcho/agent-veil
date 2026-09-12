# AgentVeil

AgentVeil is a local-first privacy control plane for AI agents. This repository
currently contains the phase-one domain contracts and security baseline described
in [`doc/06-development-roadmap.md`](doc/06-development-roadmap.md).

Implemented foundations:

- domain models for agents, egress surfaces, manifests, routes, plans, sessions,
  findings, policies, networking and audit events;
- fail-closed validation with stable error and risk codes;
- capability-based coverage planning that cannot label incomplete inspection as
  `Protected`;
- deterministic session-scoped placeholders and a bounded request-scoped memory
  vault;
- exact upstream allowlisting with HTTPS-by-default and loopback-only HTTP;
- metadata-only audit events and workspace-path hashing.

Run the tests with:

```bash
go test ./...
```

The product documents describe the complete target product. Features from later
roadmap phases are not represented as complete merely because their contracts
exist here.
