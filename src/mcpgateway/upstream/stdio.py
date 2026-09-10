"""stdio transport: spawn an upstream MCP server and talk newline-delimited JSON."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from .base import Upstream

log = logging.getLogger(__name__)

# Upstream servers can emit large tool catalogues in a single frame.
MAX_LINE_BYTES = 8 * 1024 * 1024


class StdioUpstream(Upstream):
    def __init__(
        self,
        name: str,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        *,
        timeout: float = 30.0,
        inherit_env: bool = False,
    ) -> None:
        super().__init__(name, timeout=timeout)
        self.command = command
        self.args = args or []
        # Do not leak the gateway's own environment (which holds its secrets)
        # into upstream processes unless explicitly asked to.
        base_env = dict(os.environ) if inherit_env else {"PATH": os.environ.get("PATH", "")}
        self.env = {**base_env, **(env or {})}
        self.cwd = cwd
        self._proc: asyncio.subprocess.Process | None = None
        self._pending: dict[Any, asyncio.Future] = {}
        self._reader: asyncio.Task | None = None
        self._stderr_reader: asyncio.Task | None = None
        self._write_lock = asyncio.Lock()

    async def _connect(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            self.command,
            *self.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env,
            cwd=self.cwd,
            limit=MAX_LINE_BYTES,
        )
        self._reader = asyncio.create_task(self._read_loop(), name=f"stdio-read-{self.name}")
        self._stderr_reader = asyncio.create_task(
            self._drain_stderr(), name=f"stdio-err-{self.name}"
        )

    async def _read_loop(self) -> None:
        assert self._proc and self._proc.stdout
        try:
            while True:
                line = await self._proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    log.warning("upstream %s wrote non-JSON to stdout: %r", self.name, line[:200])
                    continue
                self._dispatch(message)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("read loop for upstream %s failed", self.name)
        finally:
            self._fail_pending("upstream connection closed")

    def _dispatch(self, message: dict[str, Any]) -> None:
        message_id = message.get("id")
        future = self._pending.pop(message_id, None)
        if future is not None and not future.done():
            future.set_result(message)
        elif message_id is None:
            # Server-initiated notification; nothing subscribes to these yet.
            log.debug("upstream %s notification: %s", self.name, message.get("method"))

    async def _drain_stderr(self) -> None:
        assert self._proc and self._proc.stderr
        try:
            while True:
                line = await self._proc.stderr.readline()
                if not line:
                    break
                log.debug("[%s stderr] %s", self.name, line.decode(errors="replace").rstrip())
        except asyncio.CancelledError:
            raise
        except Exception:
            log.debug("stderr reader for upstream %s stopped", self.name, exc_info=True)

    def _fail_pending(self, reason: str) -> None:
        for future in self._pending.values():
            if not future.done():
                future.set_exception(ConnectionError(reason))
        self._pending.clear()

    async def _send(self, payload: dict[str, Any], *, expect_response: bool):
        if self._proc is None or self._proc.stdin is None:
            raise ConnectionError(f"upstream '{self.name}' is not running")
        future: asyncio.Future | None = None
        if expect_response:
            future = asyncio.get_running_loop().create_future()
            self._pending[payload["id"]] = future
        data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        async with self._write_lock:
            self._proc.stdin.write(data)
            await self._proc.stdin.drain()
        if future is None:
            return None
        return await future

    async def aclose(self) -> None:
        for task in (self._reader, self._stderr_reader):
            if task is not None:
                task.cancel()
        self._fail_pending("gateway shutting down")
        if self._proc is not None and self._proc.returncode is None:
            try:
                if self._proc.stdin is not None:
                    self._proc.stdin.close()
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except (TimeoutError, ProcessLookupError):
                try:
                    self._proc.kill()
                except ProcessLookupError:
                    pass
        self.connected = False
