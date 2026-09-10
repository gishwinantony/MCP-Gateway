"""Minimal JSON-RPC 2.0 primitives.

MCP is JSON-RPC 2.0 over a transport (stdio or streamable HTTP). The gateway
speaks both sides of the protocol, so these helpers are shared by the
downstream server and the upstream clients.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

JSONRPC_VERSION = "2.0"

# Standard JSON-RPC error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# Gateway-specific codes (JSON-RPC reserves -32000..-32099 for servers).
UNAUTHORIZED = -32001
FORBIDDEN = -32002
RATE_LIMITED = -32003
UPSTREAM_ERROR = -32004
QUARANTINED = -32005


class JsonRpcError(Exception):
    """An error that can be serialised straight into a JSON-RPC error object."""

    def __init__(self, code: int, message: str, data: Any | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def to_dict(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return error


@dataclass(slots=True)
class Request:
    method: str
    params: dict[str, Any] = field(default_factory=dict)
    id: Any | None = None

    @property
    def is_notification(self) -> bool:
        return self.id is None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Request:
        if not isinstance(payload, dict):
            raise JsonRpcError(INVALID_REQUEST, "request must be a JSON object")
        method = payload.get("method")
        if not isinstance(method, str):
            raise JsonRpcError(INVALID_REQUEST, "missing or invalid 'method'")
        params = payload.get("params") or {}
        if not isinstance(params, dict):
            raise JsonRpcError(INVALID_PARAMS, "'params' must be an object")
        return cls(method=method, params=params, id=payload.get("id"))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": self.method}
        if self.params:
            payload["params"] = self.params
        if self.id is not None:
            payload["id"] = self.id
        return payload


def result_response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def error_response(request_id: Any, error: JsonRpcError) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error.to_dict()}


def notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": method}
    if params:
        payload["params"] = params
    return payload
