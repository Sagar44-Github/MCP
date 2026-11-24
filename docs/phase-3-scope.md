# Phase 3 — Classification and provenance

## Included

- Reader fixture labels and source URIs are checked against gateway-owned trusted metadata.
- The gateway tracks object IDs, source server/tool, parent IDs, transformation and lineage confidence without retaining object payloads.
- Outbound payloads must match the registered object's SHA-256 fingerprint; a known object ID cannot be reused to relabel arbitrary text.
- Derived objects inherit the highest known parent sensitivity: `PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED`.
- Missing/untrusted parents block processing and remain `UNKNOWN` in the audit; incomplete confidence or inconsistent processor metadata cannot produce a trusted derived label.
- The processor accepts trusted object IDs rather than caller-supplied content or labels; sink policy uses the label resolved from the gateway registry.
- Each sink destination attempt is attached to its source object, verdict, policy version, reason and downstream execution outcome.
- `GET /api/lineage/{trace_id}` returns source, derived and destination nodes plus their connected edges.
- The dashboard includes a live lineage panel and a mixed-parent demo: Public + Confidential → Confidential derived object → approved local sink (`WARN`).

## Demonstrations

1. **Public source:** Public source → Public summary → approved local sink (`ALLOW`).
2. **Mixed parents:** Public + Confidential sources → Confidential summary → approved local sink (`WARN`).
3. **Blocked destination:** Confidential source → Confidential summary → external destination (`BLOCK`, no sink execution).

## Boundaries

Provenance is in-memory and resets when the gateway restarts. The reader and processor are controlled synthetic demo servers. This phase does not add authenticated agent identity, persistent lineage storage, arbitrary document classification, or a reviewed declassification path. Automated testing remains planned for Phase 8 per the project schedule.
