# Phase 6 — Exact-request approval workflow

## Included

- A verified `RESTRICTED` fixture sent to the trusted local sink receives an `ASK` verdict. Sentinel records a server-side pending action and does not forward it.
- Pending action data binds the tool, exact canonical arguments (including payload), normalized destination, request/trace/session IDs, approver context, policy version and configuration fingerprint, expiry, and a SHA-256 request hash.
- The Approvals page shows the data label, object, destination, policy reason/version, expiry, argument names, payload byte count and hash. Raw payload text stays server-side and is excluded from the approval API response.
- A separate loopback-only decision route requires a demo approver token and a rationale. Approval does not itself execute the tool. A second authenticated action re-evaluates the current policy and executes the saved exact request once.
- Denial marks the request terminal with downstream execution false. Expired, changed, policy-stale, already-used, or replayed approvals cannot execute.
- Policy configuration is fingerprinted and refreshed before gateway calls, so a configuration change between approval and execution invalidates the grant and fails closed.
- The local demo reset clears pending approval state as well as events, lineage and the sink counter.

## Boundaries

Approvals and audit history live in memory and disappear on backend restart. The default approver token is a local demonstration credential, not production identity or access control. The workflow accepts only the synthetic restricted fixture and the exact trusted local sink. Persistent approvals, multi-user identity, and durable audit records are not part of this phase. Full negative-case testing remains scheduled for Phase 8.
