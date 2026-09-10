"""Aggregated view of every upstream tool, with pinning and quarantine state.

A tool becomes callable only if it passes the scanner *and* its fingerprint
matches the pinned one. Pinning is what catches a "rug pull": a server that
serves a benign definition during review and a malicious one afterwards.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .protocol import ToolDef
from .scanner import ScanResult, ToolScanner, Verdict

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Pin:
    fingerprint: str
    approved_by: str
    approved_at: float
    note: str = ""


@dataclass(slots=True)
class RegisteredTool:
    tool: ToolDef
    scan: ScanResult
    quarantined: bool
    reasons: list[str] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        return self.tool.qualified_name

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.qualified_name,
            "server": self.tool.server,
            "description": self.tool.description,
            "fingerprint": self.tool.fingerprint,
            "quarantined": self.quarantined,
            "reasons": self.reasons,
            "scan": self.scan.to_dict(),
        }


class PinStore:
    """Persists approved tool fingerprints to a JSON file."""

    def __init__(self, path: str | Path | None) -> None:
        self.path = Path(path) if path else None
        self._pins: dict[str, Pin] = {}
        self.load()

    def load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text("utf-8"))
        except (json.JSONDecodeError, OSError):
            log.warning("could not read pin store at %s; starting empty", self.path)
            return
        self._pins = {
            name: Pin(
                fingerprint=entry["fingerprint"],
                approved_by=entry.get("approved_by", "unknown"),
                approved_at=entry.get("approved_at", 0.0),
                note=entry.get("note", ""),
            )
            for name, entry in raw.items()
        }

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            name: {
                "fingerprint": pin.fingerprint,
                "approved_by": pin.approved_by,
                "approved_at": pin.approved_at,
                "note": pin.note,
            }
            for name, pin in self._pins.items()
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), "utf-8")
        tmp.replace(self.path)

    def get(self, qualified_name: str) -> Pin | None:
        return self._pins.get(qualified_name)

    def approve(self, qualified_name: str, fingerprint: str, by: str, note: str = "") -> Pin:
        pin = Pin(fingerprint=fingerprint, approved_by=by, approved_at=time.time(), note=note)
        self._pins[qualified_name] = pin
        self.save()
        return pin

    def revoke(self, qualified_name: str) -> bool:
        removed = self._pins.pop(qualified_name, None) is not None
        if removed:
            self.save()
        return removed

    def all(self) -> dict[str, Pin]:
        return dict(self._pins)


class ToolRegistry:
    """Holds the merged catalogue and decides what is safe to expose."""

    def __init__(
        self,
        scanner: ToolScanner,
        pins: PinStore,
        *,
        require_pin: bool = False,
        quarantine_on_warn: bool = False,
    ) -> None:
        self.scanner = scanner
        self.pins = pins
        self.require_pin = require_pin
        self.quarantine_on_warn = quarantine_on_warn
        self._tools: dict[str, RegisteredTool] = {}
        self.generation = 0

    # --- population ------------------------------------------------------

    def replace_server(self, server: str, tools: Iterable[ToolDef]) -> list[RegisteredTool]:
        """Re-register every tool for one upstream, keeping other servers intact."""
        for name in [n for n, t in self._tools.items() if t.tool.server == server]:
            del self._tools[name]
        registered = [self._register(tool) for tool in tools]
        self.generation += 1
        return registered

    def _register(self, tool: ToolDef) -> RegisteredTool:
        scan = self.scanner.scan(tool)
        reasons: list[str] = []
        quarantined = False

        if scan.verdict is Verdict.QUARANTINE:
            quarantined = True
            reasons.append(f"scanner risk score {scan.score} at or above quarantine threshold")
        elif scan.verdict is Verdict.WARN and self.quarantine_on_warn:
            quarantined = True
            reasons.append(f"scanner risk score {scan.score} and quarantine_on_warn is enabled")

        pin = self.pins.get(tool.qualified_name)
        if pin is not None and pin.fingerprint != tool.fingerprint:
            quarantined = True
            reasons.append(
                "definition changed since approval "
                f"(pinned {pin.fingerprint[:12]}, now {tool.fingerprint[:12]})"
            )
        elif (
            pin is not None
            and pin.fingerprint == tool.fingerprint
            and quarantined
            and not any("changed since approval" in r for r in reasons)
        ):
            # An explicit human approval overrides scanner suspicion.
            quarantined = False
            reasons.append(f"approved by {pin.approved_by} despite scanner findings")
        elif pin is None and self.require_pin:
            quarantined = True
            reasons.append("no approved pin and require_pin is enabled")

        entry = RegisteredTool(tool=tool, scan=scan, quarantined=quarantined, reasons=reasons)
        self._tools[tool.qualified_name] = entry
        if quarantined:
            log.warning("quarantined tool %s: %s", tool.qualified_name, "; ".join(reasons))
        return entry

    def approve(self, qualified_name: str, by: str, note: str = "") -> RegisteredTool:
        entry = self._tools.get(qualified_name)
        if entry is None:
            raise KeyError(qualified_name)
        self.pins.approve(qualified_name, entry.tool.fingerprint, by, note)
        return self._register(entry.tool)

    def revoke(self, qualified_name: str) -> RegisteredTool | None:
        self.pins.revoke(qualified_name)
        entry = self._tools.get(qualified_name)
        return self._register(entry.tool) if entry else None

    # --- queries ---------------------------------------------------------

    def get(self, qualified_name: str) -> RegisteredTool | None:
        return self._tools.get(qualified_name)

    def all(self) -> list[RegisteredTool]:
        return list(self._tools.values())

    def callable_tools(self) -> list[RegisteredTool]:
        return [t for t in self._tools.values() if not t.quarantined]

    def quarantined_tools(self) -> list[RegisteredTool]:
        return [t for t in self._tools.values() if t.quarantined]

    def stats(self) -> dict[str, Any]:
        servers: dict[str, int] = {}
        for entry in self._tools.values():
            servers[entry.tool.server] = servers.get(entry.tool.server, 0) + 1
        return {
            "total": len(self._tools),
            "callable": len(self.callable_tools()),
            "quarantined": len(self.quarantined_tools()),
            "by_server": servers,
            "generation": self.generation,
        }
