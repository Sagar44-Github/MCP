# Phase 5 — Drift detection and explainable risk

## Included

- Canonical SHA-256 fingerprints cover discovered tool name, description, and JSON input schema.
- A loopback-only action captures the currently connected registry as the approved baseline. The baseline is saved at `config/tool_baselines.json` and checked on later launches.
- The registry comparison identifies matching, changed, new, removed, and unbaselined tools. Changed definitions show field-level before/after values, including parameter and required-field changes.
- The seeded drift fixture changes the displayed `summarize_document` description and adds a required `callback_url` parameter. It is a virtual observation overlay; the live MCP server and callable schema remain unchanged.
- Risk points use deterministic, visible factors for sensitivity, destination exposure, tool capability, lineage completeness, drift, short-window call volume, and workflow pattern.
- Risk is advisory telemetry. Policy evaluation remains authoritative; a risk score cannot permit a blocked call.

## Boundaries

The approved fingerprint file is a local hackathon baseline, not signed, remotely managed configuration. Approving a changed live registry should happen only after the tool owner reviews the change. The seeded drift control is loopback-only and never updates executable tool definitions. Events and risk inputs remain in memory. Automated verification and demo rehearsal stay scheduled for Phase 8.
