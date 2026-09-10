"""Shared behaviour for upstream MCP server connections."""

from __future__ import annotations

import abc
import asyncio
import logging
from typing import Any

from ..jsonrpc import UPSTREAM_ERROR, JsonRpcError
from ..protocol import INITIALIZE, INITIALIZED, PROTOCOL_VERSION, TOOLS_LIST, ToolDef

log = logging.getLogger(__name__)

CLIENT_INFO = {"name": "mcp-gateway", "version": "0.1.0"}


class UpstreamUnavailable(RuntimeError):
    """Raised when a configured upstream cannot be reached."""


class Upstream(abc.ABC):
    """One connection to one upstream MCP server."""

    def __init__(self, name: str, *, timeout: float = 30.0) -> None:
        self.name = name
        self.timeout = timeout
        self.server_info: dict[str, Any] = {}
        self.capabilities: dict[str, Any] = {}
        self.connected = False
        self.last_error: str | None = None

    # --- transport hooks -------------------------------------------------

    @abc.abstractmethod
    async def _connect(self) -> None: ...

    @abc.abstractmethod
    async def _send(self, payload: dict[str, Any], *, expect_response: bool) -> dict[str, Any] | None: ...

    @abc.abstractmethod
    async def aclose(self) -> None: ...

    # --- protocol --------------------------------------------------------

    async def start(self) -> None:
        try:
            await self._connect()
            init = await self.request(
                INITIALIZE,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"roots": {"listChanged": False}},
                    "clientInfo": CLIENT_INFO,
                },
            )
            self.server_info = init.get("serverInfo", {})
            self.capabilities = init.get("capabilities", {})
            await self.notify(INITIALIZED)
            self.connected = True
            self.last_error = None
        except Exception as exc:
            self.connected = False
            self.last_error = f"{type(exc).__name__}: {exc}"
            raise UpstreamUnavailable(self.last_error) from exc

    async def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": method}
        if params:
            payload["params"] = params
        try:
            response = await asyncio.wait_for(
                self._send(payload, expect_response=True), timeout=self.timeout
            )
        except TimeoutError as exc:
            raise JsonRpcError(
                UPSTREAM_ERROR, f"upstream '{self.name}' timed out after {self.timeout}s"
            ) from exc
        if response is None:
            raise JsonRpcError(UPSTREAM_ERROR, f"upstream '{self.name}' returned no response")
        if "error" in response:
            err = response["error"]
            raise JsonRpcError(
                UPSTREAM_ERROR,
                f"upstream '{self.name}': {err.get('message', 'unknown error')}",
                data={"upstream_code": err.get("code"), "upstream_data": err.get("data")},
            )
        return response.get("result") or {}

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload = {"jsonrpc": "2.0", "method": method}
        if params:
            payload["params"] = params
        await self._send(payload, expect_response=False)

    async def list_tools(self) -> list[ToolDef]:
        """Page through tools/list and return the upstream's full catalogue."""
        tools: list[ToolDef] = []
        cursor: str | None = None
        while True:
            params = {"cursor": cursor} if cursor else {}
            result = await self.request(TOOLS_LIST, params)
            for raw in result.get("tools", []):
                try:
                    tools.append(ToolDef.from_mcp(self.name, raw))
                except KeyError:
                    log.warning("upstream %s returned a tool without a name", self.name)
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools

    _counter = 0

    def _next_id(self) -> int:
        self._counter += 1
        return self._counter
