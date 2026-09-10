"""Streamable HTTP transport for remote MCP servers.

Remote servers may answer a POST with either a plain JSON body or an SSE
stream, so both shapes are handled here.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from .base import Upstream

log = logging.getLogger(__name__)

SESSION_HEADER = "Mcp-Session-Id"


class HttpUpstream(Upstream):
    def __init__(
        self,
        name: str,
        url: str,
        headers: dict[str, str] | None = None,
        *,
        timeout: float = 30.0,
        verify_tls: bool = True,
    ) -> None:
        super().__init__(name, timeout=timeout)
        self.url = url
        self.headers = headers or {}
        self.verify_tls = verify_tls
        self.session_id: str | None = None
        self._client: httpx.AsyncClient | None = None

    async def _connect(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            verify=self.verify_tls,
            follow_redirects=True,
        )

    async def _send(self, payload: dict[str, Any], *, expect_response: bool):
        if self._client is None:
            raise ConnectionError(f"upstream '{self.name}' is not connected")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self.headers,
        }
        if self.session_id:
            headers[SESSION_HEADER] = self.session_id

        response = await self._client.post(self.url, json=payload, headers=headers)
        if response.status_code >= 400:
            raise ConnectionError(
                f"upstream '{self.name}' returned HTTP {response.status_code}: "
                f"{response.text[:200]}"
            )

        returned_session = response.headers.get(SESSION_HEADER)
        if returned_session:
            self.session_id = returned_session

        if not expect_response or response.status_code == 202:
            return None

        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            return self._parse_sse(response.text, payload.get("id"))
        if not response.content:
            return None
        return response.json()

    @staticmethod
    def _parse_sse(body: str, request_id: Any) -> dict[str, Any] | None:
        """Return the first SSE data frame whose JSON-RPC id matches."""
        fallback: dict[str, Any] | None = None
        for raw_line in body.splitlines():
            if not raw_line.startswith("data:"):
                continue
            chunk = raw_line[len("data:") :].strip()
            if not chunk:
                continue
            try:
                message = json.loads(chunk)
            except json.JSONDecodeError:
                continue
            if message.get("id") == request_id:
                return message
            fallback = fallback or message
        return fallback

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self.connected = False
