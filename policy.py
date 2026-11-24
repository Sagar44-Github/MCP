from __future__ import annotations

import json
import posixpath
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from pydantic import BaseModel


class PolicyDecision(BaseModel):
    verdict: Literal["ALLOW", "WARN", "ASK", "BLOCK"]
    policy_id: str
    policy_version: str
    reasons: list[str]
    normalized_destination: str | None = None


def normalize_destination(value: Any) -> tuple[str | None, bool, str | None]:
    """Return canonical URL, external flag, and a safe parse error."""
    if not isinstance(value, str) or not value.strip() or any(ord(char) < 32 for char in value):
        return None, False, "Destination is missing or contains invalid characters."
    try:
        parsed = urlsplit(value.strip())
        scheme = parsed.scheme.lower()
        if scheme == "local":
            host = (parsed.hostname or "").rstrip(".").lower()
            if not host or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
                return None, False, "Local destination must be a plain local://host address."
            if parsed.path not in ("", "/"):
                return None, False, "Local destination paths are not accepted."
            return f"local://{host}", False, None
        if scheme not in ("http", "https") or not parsed.hostname:
            return None, False, "Destination must use an absolute local, HTTP, or HTTPS URL."
        if parsed.username or parsed.password or parsed.fragment:
            return None, True, "Credentials and fragments are not accepted in destinations."
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port
        if port and not 1 <= port <= 65535:
            return None, True, "Destination port is outside the valid range."
        if (scheme, port) in (("http", 80), ("https", 443)):
            port = None
        netloc = f"[{host}]" if ":" in host else host
        if port:
            netloc = f"{netloc}:{port}"
        path = quote(posixpath.normpath(unquote(parsed.path or "/")), safe="/:@!$&'()*+,;=-._~")
        return urlunsplit((scheme, netloc, path, parsed.query, "")), True, None
    except (UnicodeError, ValueError):
        return None, False, "Destination could not be normalized safely."


class PolicyEngine:
    def __init__(self, config_path: Path) -> None:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        self.policy_id = raw["policy_id"]
        self.version = raw["version"]
        self.default_agent = raw["default_agent"]
        self.agents = raw["agents"]
        trusted_destinations: set[str] = set()
        for entry in raw["trusted_destinations"]:
            normalized, _, error = normalize_destination(entry)
            if error or normalized is None:
                raise ValueError(f"Invalid trusted destination entry: {error or 'empty value'}")
            trusted_destinations.add(normalized)
        self.trusted_destinations = trusted_destinations
        self.rules = raw.get("rules", [])
        self.unknown_external_verdict = raw.get("unknown_lineage_external_verdict", "BLOCK")
        if self.unknown_external_verdict not in ("BLOCK", "ASK"):
            raise ValueError("unknown_lineage_external_verdict must be BLOCK or ASK")

    def _decision(
        self,
        verdict: Literal["ALLOW", "WARN", "ASK", "BLOCK"],
        rule: str,
        reason: str,
        destination: str | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            verdict=verdict,
            policy_id=f"{self.policy_id}:{rule}",
            policy_version=self.version,
            reasons=[reason],
            normalized_destination=destination,
        )

    def evaluate(
        self,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        schema_error: str | None = None,
    ) -> PolicyDecision:
        agent = self.agents.get(agent_id)
        if agent is None:
            return self._decision("BLOCK", "AGENT-UNKNOWN", f"Agent '{agent_id}' is not registered.")
        if tool_name in agent.get("deny", ()) or tool_name not in agent.get("allow", ()):
            return self._decision("BLOCK", "TOOL-ACCESS", f"Agent '{agent_id}' is not authorized to use '{tool_name}'.")
        if schema_error:
            return self._decision("BLOCK", "ARGUMENT-SCHEMA", schema_error)

        if tool_name != "deliver_to_sink":
            return self._decision("ALLOW", "TOOL-ALLOW", f"Agent '{agent_id}' is authorized for '{tool_name}'.")

        destination, external, parse_error = normalize_destination(arguments.get("destination"))
        if parse_error:
            return self._decision("BLOCK", "DESTINATION-INVALID", parse_error)
        assert destination is not None
        label = str(arguments.get("label", "UNKNOWN")).strip().upper()
        if external and label in {"CONFIDENTIAL", "RESTRICTED"}:
            return self._decision(
                "BLOCK", "SENSITIVE-EXTERNAL",
                f"{label.title()} data cannot be sent to an external destination.", destination,
            )
        if external and label in {"UNKNOWN", ""}:
            return self._decision(
                self.unknown_external_verdict, "UNKNOWN-EXTERNAL",
                "Unknown data lineage cannot be sent to an external destination.", destination,
            )
        if destination not in self.trusted_destinations:
            return self._decision(
                "BLOCK", "DESTINATION-UNTRUSTED",
                "Destination is not in the exact trusted-destination registry.", destination,
            )
        if label == "RESTRICTED":
            return self._decision("ASK", "RESTRICTED-DATA", "Restricted data requires an exact-request demo approver before the trusted local delivery.", destination)
        if label == "CONFIDENTIAL":
            return self._decision("WARN", "CONFIDENTIAL-INTERNAL", "Confidential data is limited to the approved local sink.", destination)
        if label == "INTERNAL":
            return self._decision("WARN", "INTERNAL-SINK", "Internal data is routed to the approved local sink.", destination)
        if label != "PUBLIC":
            return self._decision("BLOCK", "LABEL-UNKNOWN", "Unrecognized data label fails closed.", destination)
        return self._decision("ALLOW", "PUBLIC-TRUSTED-SINK", "Public data may reach the approved local sink.", destination)
