"""MCP method names, versions and the gateway's internal tool model."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

# Client -> server methods.
INITIALIZE = "initialize"
PING = "ping"
TOOLS_LIST = "tools/list"
TOOLS_CALL = "tools/call"
RESOURCES_LIST = "resources/list"
PROMPTS_LIST = "prompts/list"

# Notifications.
INITIALIZED = "notifications/initialized"
TOOLS_LIST_CHANGED = "notifications/tools/list_changed"

# Separator between upstream server name and the tool's own name. Double
# underscore keeps qualified names inside the [a-zA-Z0-9_-] character class
# that most model providers enforce on tool names.
NAMESPACE_SEP = "__"


def qualify(server: str, tool: str) -> str:
    return f"{server}{NAMESPACE_SEP}{tool}"


def unqualify(qualified: str) -> tuple[str, str]:
    server, sep, tool = qualified.partition(NAMESPACE_SEP)
    if not sep:
        raise ValueError(f"'{qualified}' is not a namespaced tool name")
    return server, tool


def canonical_json(value: Any) -> str:
    """Stable JSON encoding used for fingerprints and audit hashes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(slots=True)
class ToolDef:
    """A tool as advertised by an upstream server, plus gateway metadata."""

    server: str
    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)
    title: str | None = None

    @property
    def qualified_name(self) -> str:
        return qualify(self.server, self.name)

    @property
    def fingerprint(self) -> str:
        """Content hash of everything the model can see.

        Pinning this is what makes a silent redefinition ("rug pull") of an
        already-approved tool detectable.
        """
        payload = canonical_json(
            {
                "name": self.name,
                "title": self.title,
                "description": self.description,
                "input_schema": self.input_schema,
                "annotations": self.annotations,
            }
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_mcp(self) -> dict[str, Any]:
        """Serialise back into an MCP tool object under the qualified name."""
        payload: dict[str, Any] = {
            "name": self.qualified_name,
            "description": self.description,
            "inputSchema": self.input_schema or {"type": "object", "properties": {}},
        }
        if self.title:
            payload["title"] = self.title
        if self.annotations:
            payload["annotations"] = self.annotations
        return payload

    @classmethod
    def from_mcp(cls, server: str, payload: dict[str, Any]) -> ToolDef:
        return cls(
            server=server,
            name=payload["name"],
            description=payload.get("description") or "",
            input_schema=payload.get("inputSchema") or {},
            annotations=payload.get("annotations") or {},
            title=payload.get("title"),
        )
