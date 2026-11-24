from __future__ import annotations

import hashlib
import sys
import threading
from datetime import datetime, timezone
from typing import Literal

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel


class Document(BaseModel):
    object_id: str
    title: str
    label: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "UNKNOWN"]
    source: str
    content: str
    parent_ids: list[str]
    transformation: str | None
    lineage_confidence: float


class DerivedDocument(BaseModel):
    object_id: str
    title: str
    label: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "UNKNOWN"]
    source: str
    summary: str
    parent_ids: list[str]
    transformation: str
    lineage_confidence: float


class SinkReceipt(BaseModel):
    object_id: str
    label: str
    destination: str
    trace_id: str
    bytes_received: int
    payload_sha256: str
    execution_count: int
    received_at: str


class SinkStatus(BaseModel):
    server: str
    execution_count: int
    last_receipt: SinkReceipt | None


class SinkReset(BaseModel):
    server: str
    execution_count: int
    reset_at: str


FIXTURE_RECORDS = {
    "public": {
        "object_id": "doc_public_001",
        "title": "Community garden schedule",
        "label": "PUBLIC",
        "source": "reader://fixtures/community-garden",
        "content": (
            "The Riverside community garden opens Saturday at 9:00. "
            "Volunteers will plant herbs, repair two raised beds, and share seedlings."
        ),
        "parent_ids": [],
        "transformation": None,
        "lineage_confidence": 1.0,
    },
    "confidential": {
        "object_id": "doc_confidential_001",
        "title": "Fictional launch planning notes",
        "label": "CONFIDENTIAL",
        "source": "reader://fixtures/fictional-launch-notes",
        "content": (
            "Fictional exercise only: Project Northstar plans a preview on 18 March. "
            "The internal rehearsal is scheduled for 12 March with a twelve-person team."
        ),
        "parent_ids": [],
        "transformation": None,
        "lineage_confidence": 1.0,
    },
    "restricted": {
        "object_id": "doc_restricted_001",
        "title": "Fictional restricted case file",
        "label": "RESTRICTED",
        "source": "reader://fixtures/fictional-case-file",
        "content": (
            "Fictional hackathon fixture: Case Orion access code is ORION-4821. "
            "This synthetic value exists only to demonstrate a gated local delivery."
        ),
        "parent_ids": [],
        "transformation": None,
        "lineage_confidence": 1.0,
    },
}
FIXTURE_BY_OBJECT_ID = {
    fixture["object_id"]: fixture for fixture in FIXTURE_RECORDS.values()
}
SENSITIVITY_ORDER = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}


_SINK_LOCK = threading.Lock()
_SINK_EXECUTION_COUNT = 0
_LAST_RECEIPT: SinkReceipt | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_reader() -> MCPServer:
    server = MCPServer(
        "Sentinel Reader",
        instructions="Returns synthetic fixtures only. No filesystem or external network access is provided.",
    )

    @server.tool(title="Read a synthetic document")
    def read_document(document_id: str = "public") -> Document:
        """Read one of the controlled public or fictional confidential fixtures."""
        fixture = FIXTURE_RECORDS.get(document_id.strip().lower())
        if fixture is None:
            raise ToolError("Unknown fixture. Choose 'public' or 'confidential'.")
        return Document(**fixture)

    return server


def build_processor() -> MCPServer:
    server = MCPServer(
        "Sentinel Processor",
        instructions="Creates synthetic summaries and returns the source object lineage metadata.",
    )

    @server.tool(title="Summarize a document")
    def summarize_document(parent_ids: list[str]) -> DerivedDocument:
        """Summarize trusted fixture objects and retain their combined sensitivity."""
        if not parent_ids or any(not parent_id.strip() for parent_id in parent_ids):
            raise ToolError("At least one source object ID is required.")
        if len(set(parent_ids)) != len(parent_ids):
            raise ToolError("Parent object IDs must be unique.")
        parents = [FIXTURE_BY_OBJECT_ID.get(parent_id) for parent_id in parent_ids]
        if any(parent is None for parent in parents):
            raise ToolError("A parent object is missing from the trusted fixture registry.")
        trusted_parents = [parent for parent in parents if parent is not None]
        label = max(
            (str(parent["label"]) for parent in trusted_parents),
            key=lambda value: SENSITIVITY_ORDER[value],
        )
        source = " | ".join(str(parent["source"]) for parent in trusted_parents)
        content = "\n".join(str(parent["content"]) for parent in trusted_parents)
        words = content.split()
        summary = " ".join(words[:24])
        if len(words) > 24:
            summary = f"{summary}…"
        stable_parent_key = ":".join(sorted(parent_ids))
        derived_id = "derived_" + hashlib.sha256(stable_parent_key.encode("utf-8")).hexdigest()[:12]
        return DerivedDocument(
            object_id=derived_id,
            title="Summary of source document",
            label=label,
            source=source,
            summary=summary,
            parent_ids=parent_ids,
            transformation="extractive-summary-v1",
            lineage_confidence=1.0,
        )

    return server


def build_sink() -> MCPServer:
    server = MCPServer(
        "Sentinel Sink",
        instructions="Local demo receiver. Stores receipt metadata and payload hash, never raw payload text.",
    )

    @server.tool(title="Deliver to local demo sink")
    def deliver_to_sink(
        object_id: str,
        label: str,
        destination: str,
        trace_id: str,
        payload: str,
    ) -> SinkReceipt:
        """Record one local receipt and return the sink's server-side execution count."""
        global _SINK_EXECUTION_COUNT, _LAST_RECEIPT
        if destination != "local://sentinel-demo-sink":
            raise ToolError("The controlled sink accepts only local://sentinel-demo-sink.")
        if not trace_id.strip() or not object_id.strip():
            raise ToolError("A trace ID and object ID are required.")
        payload_bytes = payload.encode("utf-8")
        with _SINK_LOCK:
            _SINK_EXECUTION_COUNT += 1
            _LAST_RECEIPT = SinkReceipt(
                object_id=object_id,
                label=label,
                destination=destination,
                trace_id=trace_id,
                bytes_received=len(payload_bytes),
                payload_sha256=hashlib.sha256(payload_bytes).hexdigest(),
                execution_count=_SINK_EXECUTION_COUNT,
                received_at=utc_now(),
            )
            return _LAST_RECEIPT

    @server.tool(title="Read sink execution status")
    def get_sink_status() -> SinkStatus:
        """Read the local sink's live server-side execution count and last receipt."""
        with _SINK_LOCK:
            return SinkStatus(
                server="sentinel-demo-sink",
                execution_count=_SINK_EXECUTION_COUNT,
                last_receipt=_LAST_RECEIPT,
            )

    @server.tool(title="Reset local demo sink")
    def reset_sink() -> SinkReset:
        """Reset the local sink state for a clearly labeled demo rehearsal."""
        global _SINK_EXECUTION_COUNT, _LAST_RECEIPT
        with _SINK_LOCK:
            _SINK_EXECUTION_COUNT = 0
            _LAST_RECEIPT = None
            return SinkReset(
                server="sentinel-demo-sink",
                execution_count=0,
                reset_at=utc_now(),
            )

    return server


SERVERS = {
    "reader": build_reader,
    "processor": build_processor,
    "sink": build_sink,
}


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in SERVERS:
        raise SystemExit("Usage: python mcp_servers.py <reader|processor|sink>")
    SERVERS[sys.argv[1]]().run(transport="stdio")


if __name__ == "__main__":
    main()
