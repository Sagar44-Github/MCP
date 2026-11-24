# Phase 7 — ElevenLabs incident briefing

## Included

- The Overview voice card exposes the text query **Explain last blocked event** and resolves the newest real `BLOCK` from Sentinel's in-memory incident API.
- The backend builds a short briefing from the event's trusted label, allowlisted tool/server name, fixed policy-rule explanation, and downstream execution state. It does not use event arguments, raw payloads, or arbitrary client-supplied text.
- The text briefing is returned first and remains available as a fallback if speech is not configured or the provider request fails.
- When `ELEVENLABS_API_KEY` is set, the browser can request an MP3 for that event and use explicit Play/Stop controls. The key stays in the backend. Voice ID and model are configurable with `ELEVENLABS_VOICE_ID` and `ELEVENLABS_MODEL_ID`.
- Speech requests are loopback-only, limited to recorded BLOCK events, capped to a short text and 2 MiB audio response, and cached per event for the backend process to avoid repeat synthesis charges.
- No speech-to-text, voice commands, approvals, policy changes, or tool execution are exposed through the voice feature.

## Boundaries

The API key and an eligible ElevenLabs account/voice must be supplied by the project owner to hear generated speech. If the key is absent, fails, or reaches a provider limit, the incident text still works. The backend sends the key as the provider's authentication header and sends the short sanitized briefing for synthesis; the key is never sent to the browser. Audio is generated only after a user click and sent to the configured ElevenLabs account; provider-side retention follows that account's settings. Audio cache and incident events are in-memory and are cleared by the local demo reset or backend restart. No AWS integration is included.
