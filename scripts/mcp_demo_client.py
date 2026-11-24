from __future__ import annotations

import argparse
import asyncio
import json
import os
from typing import Any

from mcp import Client


async def main(url: str, scenario: str) -> None:
    async with Client(url) as client:
        tools = await client.list_tools()
        print("Sentinel MCP tools:", ", ".join(tool.name for tool in tools.tools))
        response = await client.call_tool("run_public_journey", {"scenario": scenario})
        if response.is_error:
            details = [getattr(block, "text", "") for block in response.content]
            raise RuntimeError("MCP journey failed: " + "; ".join(text for text in details if text))
        result: Any = response.structured_content
        if result is None:
            raise RuntimeError("Sentinel returned no structured MCP result.")
        receipt = result.get("receipt") or {}
        derived = result.get("derived") or {}
        print(
            json.dumps(
                {
                    "trace_id": result.get("trace_id"),
                    "request_id": result.get("request_id"),
                    "verdict": result.get("verdict"),
                    "policy": result.get("decision", {}).get("policy_id"),
                    "mcp_steps": [step.get("tool") for step in result.get("steps", [])],
                    "source_labels": [source.get("label") for source in result.get("sources", [])],
                    "derived_object": {
                        "object_id": derived.get("object_id"),
                        "label": derived.get("label"),
                        "parent_ids": derived.get("parent_ids"),
                        "transformation": derived.get("transformation"),
                    },
                    "lineage_edges": (result.get("lineage") or {}).get("edges", []),
                    "sink_execution_before": result.get("sink_execution_before"),
                    "sink_execution_after": result.get("sink_execution_after"),
                    "sink_execution_count": receipt.get("execution_count"),
                    "payload_sha256": receipt.get("payload_sha256"),
                    "pending_approval": (
                        {
                            "action_id": result["pending_approval"].get("action_id"),
                            "status": result["pending_approval"].get("status"),
                            "expires_at": result["pending_approval"].get("expires_at"),
                            "payload": (result["pending_approval"].get("sanitized_arguments") or {}).get("payload"),
                        }
                        if result.get("pending_approval") else None
                    ),
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Call MCP Sentinel over Streamable HTTP.")
    parser.add_argument(
        "--url",
        default=os.getenv("MCP_SENTINEL_GATEWAY_URL", "http://127.0.0.1:8000/mcp"),
        help="Sentinel MCP endpoint (default: http://127.0.0.1:8000/mcp)",
    )
    parser.add_argument(
        "--scenario",
        choices=("public_to_approved_sink", "multi_parent_inheritance", "confidential_to_external_sink", "restricted_to_approved_sink"),
        default="public_to_approved_sink",
        help="Controlled fixture scenario to call through Sentinel.",
    )
    args = parser.parse_args()
    asyncio.run(main(args.url, args.scenario))
