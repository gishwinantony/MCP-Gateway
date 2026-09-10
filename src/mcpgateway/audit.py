"""Append-only, tamper-evident audit log.

Each record embeds the hash of the previous record, so deleting or editing an
entry after the fact breaks the chain and `verify` reports exactly where.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .protocol import canonical_json

GENESIS = "0" * 64

# Argument names whose values never reach the log.
SENSITIVE_KEYS = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|authorization|credential|private[_-]?key)",
    re.IGNORECASE,
)
REDACTED = "[redacted]"


@dataclass(slots=True)
class AuditRecord:
    seq: int
    timestamp: float
    event: str
    principal: str
    tool: str
    decision: str
    detail: dict[str, Any]
    prev_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "event": self.event,
            "principal": self.principal,
            "tool": self.tool,
            "decision": self.decision,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


def redact(value: Any, depth: int = 0) -> Any:
    """Recursively redact sensitive values and truncate long strings."""
    if depth > 6:
        return "[truncated]"
    if isinstance(value, dict):
        return {
            key: (REDACTED if SENSITIVE_KEYS.search(str(key)) else redact(item, depth + 1))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item, depth + 1) for item in value[:50]]
    if isinstance(value, str) and len(value) > 512:
        return value[:512] + f"...[{len(value)} chars]"
    return value


def record_hash(payload: dict[str, Any]) -> str:
    body = {k: v for k, v in payload.items() if k != "hash"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


class AuditLog:
    """JSONL audit log. Thread-safe; one file handle held open in append mode."""

    def __init__(self, path: str | Path | None, *, redact_arguments: bool = True) -> None:
        self.path = Path(path) if path else None
        self.redact_arguments = redact_arguments
        self._lock = threading.Lock()
        self._seq = 0
        self._last_hash = GENESIS
        self._memory: list[AuditRecord] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._resume()

    def _resume(self) -> None:
        """Continue an existing chain rather than starting a new one."""
        assert self.path
        if not self.path.exists():
            return
        last: dict[str, Any] | None = None
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)
                    except json.JSONDecodeError:
                        continue
        if last:
            self._seq = int(last.get("seq", 0))
            self._last_hash = last.get("hash", GENESIS)

    def write(
        self,
        event: str,
        *,
        principal: str = "-",
        tool: str = "-",
        decision: str = "-",
        detail: dict[str, Any] | None = None,
    ) -> AuditRecord:
        payload_detail = detail or {}
        if self.redact_arguments:
            payload_detail = redact(payload_detail)
        with self._lock:
            self._seq += 1
            body = {
                "seq": self._seq,
                "timestamp": time.time(),
                "event": event,
                "principal": principal,
                "tool": tool,
                "decision": decision,
                "detail": payload_detail,
                "prev_hash": self._last_hash,
            }
            digest = record_hash(body)
            body["hash"] = digest
            self._last_hash = digest
            record = AuditRecord(**body)
            self._memory.append(record)
            if len(self._memory) > 1000:
                del self._memory[:-1000]
            if self.path:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(body, ensure_ascii=False) + "\n")
        return record

    def tail(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self._memory[-limit:]]

    def read_all(self) -> Iterator[dict[str, Any]]:
        if not self.path or not self.path.exists():
            yield from (r.to_dict() for r in self._memory)
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify(self) -> dict[str, Any]:
        """Walk the chain and report the first record that does not verify."""
        previous = GENESIS
        count = 0
        for entry in self.read_all():
            count += 1
            if entry.get("prev_hash") != previous:
                return {
                    "valid": False,
                    "checked": count,
                    "broken_at": entry.get("seq"),
                    "error": "prev_hash does not match the previous record",
                }
            expected = record_hash(entry)
            if expected != entry.get("hash"):
                return {
                    "valid": False,
                    "checked": count,
                    "broken_at": entry.get("seq"),
                    "error": "record contents do not match their hash",
                }
            previous = entry["hash"]
        return {"valid": True, "checked": count, "head": previous}
