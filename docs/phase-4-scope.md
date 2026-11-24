# Phase 4 — Live dashboard and incident view

## Included

- Overview metrics come from the gateway's live event buffer and downstream sink counter.
- The activity table reads the event API, refreshes without appending duplicate rows, and supports verdict, data-label, and text filters.
- Selecting an event opens an incident detail panel with trace/session, object and parent IDs, destination, policy version, reason, latency and downstream execution evidence.
- Incident details load the connected lineage graph from `GET /api/lineage/{trace_id}`.
- Existing tool registry, policy and lineage views remain available.
- The demo-only reset calls a `sentinel-system`-authorized sink reset tool, then clears in-memory events and lineage.
- Loading, disconnected, empty, filter-empty and API-error states are visible.

## Boundaries

Events and lineage stay in memory and reset with the local demo. The reset control is for local demonstration only; this phase adds no authentication or production operations interface. There is no seeded event data. Automated testing and demo rehearsal remain scheduled for Phase 8.
