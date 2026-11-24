# MCP Sentinel

MCP Sentinel is a security gateway prototype for AI tool calls. The implementation covers **phases 1–8**: real MCP routing, deterministic policy enforcement, trusted object classification/provenance, a live incident dashboard, approved tool-contract drift detection with explainable risk, exact-request approval, ElevenLabs incident briefings, and a local regression/rehearsal freeze.

> This is a local hackathon prototype. It demonstrates a focused allow/block policy path; it is not production authentication or complete data-loss prevention.

## Phase 1–8 demo

```text
Dashboard → Sentinel REST demo route → MCP Streamable HTTP client → Sentinel MCP gateway
                                                              → MCP stdio clients → Reader / Processor / Sink
```

Sentinel exposes `/mcp` as an MCP Streamable HTTP endpoint and launches/owns the three downstream MCP server processes over stdio. The dashboard talks only to Sentinel. Its scenario route uses the MCP client to call the Sentinel MCP server, which resolves labels and provenance before policy evaluation. Demonstrate a Public delivery (`ALLOW`), a mixed-parent summary that inherits `CONFIDENTIAL` (`WARN` at the approved local sink), a Confidential external attempt (`BLOCK` before forwarding), and a Restricted local attempt (`ASK`, held for exact-request approval). The lineage API links source objects, derived summaries and destination attempts. The sink records receipt metadata plus a payload hash rather than retaining payload text.

## Requirements

- Python 3.11 or newer
- Node.js 20 or newer
- npm

## Run locally

Open two terminals in this folder.

**Terminal 1 — API and controlled MCP servers**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

**Terminal 2 — dashboard**

```powershell
cd frontend
npm ci
npm run dev
```

Open the Vite URL printed in the second terminal (normally `http://localhost:5173`). The animated Sentinel landing page is the entry point; select **Enter live console** to open the existing dashboard. Its 3D policy core and scroll-linked transitions use Three.js with React Three Fiber and Motion for React. The geometry is generated locally in code, with no remote model or stock asset requests. The dashboard reads live data from the API; it does not seed activity or invent execution counts. Use the verdict/data-label filters and inspect an event to open its decision evidence and lineage. On **Risk & drift**, approve the connected tool definitions once to save fingerprints in `config/tool_baselines.json`. The seeded drift control demonstrates a description change and a new required parameter without changing the executable MCP tool. Risk factors use fixed, visible rules; policy decisions remain authoritative. **Reset demo state** resets the sink counter and clears in-memory events, provenance, approvals, and voice cache for a local rehearsal.

The Phase 6 approval flow uses a local demo approver token (`sentinel-demo-approver` by default). Set `MCP_SENTINEL_APPROVER_TOKEN` to a different value before launching the API to override it; tokens must be at least 12 characters. `MCP_SENTINEL_APPROVER_ID` optionally sets the audit identity. From Overview, run **Restricted · expect ASK**. The payload is shown only as a redacted byte count and hash. In **Approvals**, enter the token and rationale, approve or deny, and if approved select **Re-check policy & execute once** as a separate step. A request expires after five minutes.

Phase 7 adds **Hear the latest BLOCK explained** on Overview. It first uses the live in-memory incident API to compose a short text briefing; when ElevenLabs is configured, the same short briefing can be synthesized and played. The provider receives a fixed data label, allowlisted tool/server names, a fixed policy explanation, and the downstream execution state. Raw arguments and payload text are never sent. The backend uses the API key only for ElevenLabs authentication; the key is never sent to the browser or included in briefing text. Text fallback works without ElevenLabs. To enable speech, set `ELEVENLABS_API_KEY` before starting the backend; optionally set `ELEVENLABS_VOICE_ID` and `ELEVENLABS_MODEL_ID`. Speech is generated only after you click the briefing action and is cached per event for this process.

In PowerShell, set a private local token for the backend process with `$env:MCP_SENTINEL_APPROVER_TOKEN = 'your-private-demo-token'` before starting Uvicorn. Restart the backend after changing it.

For ElevenLabs, set `$env:ELEVENLABS_API_KEY = 'your-elevenlabs-api-key'` before starting Uvicorn. The default demo voice is George; optionally set `$env:ELEVENLABS_VOICE_ID = 'your-voice-id'` and `$env:ELEVENLABS_MODEL_ID = 'eleven_flash_v2_5'` to choose another compatible voice or model. Keep the API key on the backend; never put it in the Vite frontend.

The MCP endpoint is `http://127.0.0.1:8000/mcp`. To demonstrate a separate MCP client calling Sentinel:

```powershell
python scripts/mcp_demo_client.py
```

If you run Uvicorn on another port, set `MCP_SENTINEL_GATEWAY_URL` to that server's `/mcp` URL before starting the API.

For macOS/Linux, activate the environment with `source .venv/bin/activate` instead.

## Demo script

1. Start the API and dashboard; wait for the three MCP server indicators to show **Online**.
2. Open **Risk & drift** and select **Approve current definitions** after all servers connect.
3. Select **Simulate seeded drift**. Show the changed description, new `callback_url` parameter, and explainable risk. Clear the simulation; it does not change the running tools.
4. Select **Reset demo state** before the rehearsal to clear previous events, lineage, sink receipts, and approvals.
5. Open **Tool registry** and show that tool definitions came from MCP discovery.
6. Return to **Overview** and run **Public source · expect ALLOW**. Open **Lineage** to show its source label and parent-linked summary.
7. Run **Mix public + confidential · inherit CONFIDENTIAL**. Show the derived label remains Confidential and the local sink decision is WARN.
8. Run **Confidential · expect BLOCK**. Show the linked source → summary → external attempt and the sink counter staying unchanged.
9. Click **Explain last blocked event**. With ElevenLabs configured, play the generated voice clip; without a key, show the same text briefing fallback.
10. Run **Restricted · expect ASK**. Show the pending sanitized request and unchanged sink counter, then deny one request to demonstrate a no-forward denial.
11. Run the Restricted scenario again, approve with a rationale, and select **Re-check policy & execute once**. Show the updated sink receipt and the completed audit record. For a direct MCP-client proof, run `python scripts/mcp_demo_client.py --scenario multi_parent_inheritance`.

For a direct MCP-client approval request, `python scripts/mcp_demo_client.py --scenario restricted_to_approved_sink` creates the same pending action without forwarding. Complete its review and one-time execution in the dashboard.

The lineage endpoint is available at `http://127.0.0.1:8000/api/lineage/{trace_id}` using a trace ID returned by a scenario.

The confidential fixture is entirely fictional. Its blocked scenario uses a reserved `.example` hostname and does not connect to an external destination.

## Phase 8 verification

From a clean Python environment, install the project and run `python -m unittest discover -s tests -v`. The regression suite starts the three controlled MCP servers and checks policy outcomes against the sink's real execution counter. It simulates the ElevenLabs timeout without contacting the provider. For the dashboard, run `cd frontend`, `npm ci`, and `npm run build`. See [`docs/phase-8-scope.md`](docs/phase-8-scope.md) for the regression scope and its limits.

## Things to supply manually

- For spoken audio, create/use your own ElevenLabs API key and set `ELEVENLABS_API_KEY` in the backend terminal before Uvicorn starts. The optional `ELEVENLABS_VOICE_ID` and `ELEVENLABS_MODEL_ID` select a voice/model; text fallback works without these credentials. Do not put the key in the frontend or chat.
- For a non-default demo approver, set `MCP_SENTINEL_APPROVER_TOKEN` before starting Uvicorn and enter that same token in **Approvals**. The local demo default is `sentinel-demo-approver`; this prototype does not provision production identities.
- After all three MCP servers show **Online** on the first run, open **Risk & drift** and choose **Approve current definitions** once. This writes `config/tool_baselines.json` locally.
- If you change the backend port, update `MCP_SENTINEL_GATEWAY_URL` before launching the API. If you enable voice, use a browser with audio output available; ElevenLabs account limits and voice availability are managed by your account.

No AWS credentials are required.

## Phase notes

See [`docs/phase-1-scope.md`](docs/phase-1-scope.md), [`docs/phase-2-scope.md`](docs/phase-2-scope.md), [`docs/phase-3-scope.md`](docs/phase-3-scope.md), [`docs/phase-4-scope.md`](docs/phase-4-scope.md), [`docs/phase-5-scope.md`](docs/phase-5-scope.md), [`docs/phase-6-scope.md`](docs/phase-6-scope.md), [`docs/phase-7-scope.md`](docs/phase-7-scope.md), and [`docs/phase-8-scope.md`](docs/phase-8-scope.md) for boundaries and limitations. The original master plan remains unchanged.
The dashboard's twenty interface principles are in [`docs/design-system.md`](docs/design-system.md).
Open-source visual library licenses are listed in [`frontend/THIRD_PARTY_NOTICES.md`](frontend/THIRD_PARTY_NOTICES.md).
