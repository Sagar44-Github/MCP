# MCP Sentinel dashboard design

The dashboard uses a Vercel-inspired visual direction: near-black surfaces, precise typography, thin borders, compact labels, and one restrained lime accent. It follows the master plan's dark security-operations direction and keeps live backend state at the center of the demo.

Phase 8 adds a separate cinematic landing page with locally generated 3D gateway geometry, scroll-linked parallax and reveal transitions, a real request-path diagram, and a direct console action. The 3D scene uses React Three Fiber / Three.js; Motion for React drives scroll effects. The scene is code-split, has a WebGL fallback, limits device pixel ratio, and observes `prefers-reduced-motion`. No remote model or image asset is fetched.

## Twenty interface principles

1. **One primary action:** make the current phase's live proof the clearest next step.
2. **Clear page hierarchy:** distinguish workspace, section, panel, and field labels.
3. **Use concrete copy:** name the reader, processor, sink, trace, and outcome.
4. **Keep navigation stable:** place phase tools and server status in a persistent rail.
5. **Use backend truth:** source counts, tools, events, and health from the API.
6. **Label the phase boundary:** distinguish gateway transport, policy/provenance, phase 4 incident details, phase 5 tool integrity signals, phase 6 exact-request approvals, and phase 7 incident voice.
7. **Show the full route:** make the gateway and each controlled MCP server visible.
8. **Show both transports:** distinguish the Streamable HTTP ingress from stdio downstream links.
9. **Make traceability visible:** put the trace ID on the receipt and in each event row.
10. **Keep request identity inspectable:** pair each event with its request ID.
11. **Redact event arguments:** show field counts instead of argument values.
12. **Prefer metadata at the sink:** display a receipt hash and byte count, not retained payload text.
13. **Use progressive disclosure:** expand input schemas only when requested.
14. **Give immediate feedback:** use a busy state while a journey runs, show its receipt, and open event details on selection.
15. **Explain failures in place:** show the API or server error next to a retry action.
16. **Avoid replay ambiguity:** do not automatically retry a sink call after a lost response.
17. **Use consistent status colors and text:** pair each color with a readable state label.
18. **Keep motion restrained:** reserve animation for live status and completed receipts.
19. **Respect small screens:** stack cards and keep tables horizontally scrollable.
20. **Support accessible operation:** use semantic buttons, visible focus, and reduced-motion preferences.
