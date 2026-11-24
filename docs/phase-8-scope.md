# Phase 8 — regression and demo freeze

## Included

- `tests/test_phase8_regressions.py` exercises the public ALLOW and confidential local WARN flows against the real local MCP reader, processor, and sink processes.
- The regression matrix checks that confidential external delivery, restricted external delivery, untrusted lineage, unauthorized tools, invalid schemas, and a tampered tool output carrying prompt-injection instructions are denied before the sink runs.
- Tool schema drift, approval expiry, approval mutation, one-time approved execution, sink execution counts, lineage, and an ElevenLabs timeout fallback are covered.
- The ElevenLabs outage case is simulated locally; the suite never sends the test key or briefing text to the provider, and it never contacts an external destination.
- Tests use Python's standard `unittest` runner, so no test-only Python dependency is required.
- The demo entry page now has a code-generated 3D policy core and scroll-linked motion, with a direct one-click handoff to the live console and a text/CSS fallback if WebGL is unavailable.

## Run

From a clean Python environment, install the project and run:

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
```

Build the dashboard separately with `cd frontend; npm ci; npm run build`.

## Limits

These checks validate the local prototype and its controlled MCP subprocesses. They do not validate production authentication, cloud deployment, arbitrary MCP implementations, ElevenLabs account entitlements, or playback on a physical audio device. The example external host uses the reserved `.example` domain and is never contacted.
