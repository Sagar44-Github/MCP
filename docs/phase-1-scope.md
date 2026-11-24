# Phase 1 — Real MCP gateway and controlled servers

This records the Phase 1 foundation. Phase 2 enforcement is documented separately in [`phase-2-scope.md`](phase-2-scope.md).

## Included

- A FastAPI gateway exposing a Streamable HTTP MCP server and persistent official MCP SDK client connections.
- Three MCP stdio server processes, launched and owned by the gateway:
  - **Reader**: public and fictional confidential fixtures with object metadata.
  - **Processor**: creates a derived summary and returns its parent and transformation metadata.
  - **Sink**: records receipt metadata and increments a server-side counter.
- Startup tool discovery and a live registry view.
- Request, session, and trace IDs. One demo journey uses one trace across all three servers.
- A demo endpoint that runs the public read → summarize → local delivery path through the gateway.
- A standalone official MCP client script that calls the gateway endpoint.
- A small dashboard with live health, event history, tool registry, and sink counter.
- Visible degraded states and surfaced MCP errors. The gateway does not retry side-effecting sink calls.

## Observable proof

Run the public journey from the dashboard. The UI should show three MCP-backed steps, the same trace ID in the event stream and sink receipt, and the sink's execution count increasing once. A second journey increases it once more. No browser route connects to a protected server; the only exposed browser API is the gateway.

## Deliberately deferred

The Phase 1 transport foundation alone did not enforce policy. Phase 2 adds deterministic authorization, schema validation, destination trust, and blocking. Phase 3 adds trusted label inheritance and provenance. Production authentication remains later work.
