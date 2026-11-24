# Phase 2 — Deterministic policy and blocking

## Included

- A versioned, editable policy configuration in `config/policies.json`.
- Backend-only policy decisions; the dashboard and MCP caller cannot override a BLOCK.
- Per-agent tool allow/deny permissions.
- JSON Schema argument validation using discovered MCP tool schemas. Remote schema references are rejected.
- Destination parsing and normalization with exact trusted-destination matching.
- A label/destination matrix with ALLOW, WARN, ASK, and BLOCK verdicts. At Phase 2, ASK remains fail-closed; Phase 6 adds a narrow, exact-request approval path for the restricted local fixture.
- Policy ID, version, reason, normalized destination, and whether downstream execution occurred on every call event.
- A live dashboard policy page and two controlled demonstrations:
  - Public fixture → approved local sink: ALLOW and sink count increments once.
  - Confidential fixture → unapproved external destination: BLOCK before forwarding and sink count stays unchanged.
- A generic MCP tool proxy protected by the same policy engine.

## Current baseline

`demo-agent` may read and summarize the controlled fixtures and deliver only to `local://sentinel-demo-sink`. Public data is allowed; internal and confidential data to that sink receive WARN and are forwarded; restricted data is blocked. Confidential/restricted data to HTTP(S) destinations is blocked. Unknown data lineage to an external destination follows the configured verdict, currently BLOCK. All other destinations are blocked unless explicitly trusted.

`sentinel-system` alone may read the sink counter. The phase 2 demo uses fictional data and the reserved `.example` domain as an inert destination string; the gateway blocks before the sink tool is called.

## Deferred

Automated regression tests, authenticated agent identity, approvals, durable audit storage, and production deployment remain later work. Phase 3 adds data provenance and label inheritance. Phase 8 is the planned test and rehearsal phase.
