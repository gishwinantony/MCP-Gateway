"""Per-principal authorization, rate limiting and argument guards.

MCP itself has no concept of who is calling. The gateway adds one: every
request carries a bearer token that maps to a principal, and every principal
has an explicit allow/deny list, a rate budget, and optional guards on the
arguments of specific tools.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"
    RATE_LIMITED = "rate_limited"


@dataclass(slots=True)
class PolicyResult:
    decision: Decision
    reason: str = ""
    matched_rule: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


@dataclass(slots=True)
class ArgumentGuard:
    """Blocks a call when an argument matches a forbidden pattern."""

    tool: str
    field: str
    deny_regex: str = ""
    allow_regex: str = ""
    max_length: int | None = None

    def check(self, tool_name: str, arguments: dict[str, Any]) -> str | None:
        if not fnmatch.fnmatch(tool_name, self.tool):
            return None
        value = _dig(arguments, self.field)
        if value is None:
            return None
        text = value if isinstance(value, str) else str(value)
        if self.deny_regex and re.search(self.deny_regex, text, re.IGNORECASE):
            return f"argument '{self.field}' matches denied pattern for {self.tool}"
        if self.allow_regex and not re.search(self.allow_regex, text, re.IGNORECASE):
            return f"argument '{self.field}' does not match required pattern for {self.tool}"
        if self.max_length is not None and len(text) > self.max_length:
            return f"argument '{self.field}' exceeds max length {self.max_length}"
        return None


def _dig(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


class TokenBucket:
    """Classic token bucket. Refills continuously at `rate` tokens per second."""

    __slots__ = ("_tokens", "_updated", "capacity", "rate")

    def __init__(self, capacity: int, rate_per_minute: float) -> None:
        self.capacity = max(1, capacity)
        self.rate = rate_per_minute / 60.0
        self._tokens = float(self.capacity)
        self._updated = time.monotonic()

    def consume(self, amount: float = 1.0, *, now: float | None = None) -> bool:
        now = now if now is not None else time.monotonic()
        elapsed = max(0.0, now - self._updated)
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._updated = now
        if self._tokens >= amount:
            self._tokens -= amount
            return True
        return False

    @property
    def available(self) -> float:
        return self._tokens


@dataclass(slots=True)
class RateLimit:
    calls_per_minute: int = 60
    burst: int = 10


@dataclass
class Principal:
    id: str
    token_sha256: str = ""
    allow: list[str] = field(default_factory=lambda: ["*"])
    deny: list[str] = field(default_factory=list)
    require_approval: list[str] = field(default_factory=list)
    rate_limit: RateLimit = field(default_factory=RateLimit)
    per_tool_rate_limit: RateLimit | None = None
    argument_guards: list[ArgumentGuard] = field(default_factory=list)
    max_tools_exposed: int | None = None
    admin: bool = False

    def matches_token(self, token: str) -> bool:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return hmac.compare_digest(digest, self.token_sha256)


class PolicyEngine:
    def __init__(self, principals: Iterable[Principal]) -> None:
        self.principals = {p.id: p for p in principals}
        self._buckets: dict[str, TokenBucket] = {}
        self._approvals: set[tuple[str, str]] = set()

    # --- authentication --------------------------------------------------

    def authenticate(self, token: str | None) -> Principal | None:
        if not token:
            return None
        for principal in self.principals.values():
            if principal.token_sha256 and principal.matches_token(token):
                return principal
        return None

    # --- authorization ---------------------------------------------------

    def visible_tools(self, principal: Principal, tool_names: Iterable[str]) -> list[str]:
        return [name for name in tool_names if self._pattern_allows(principal, name)]

    def _pattern_allows(self, principal: Principal, tool_name: str) -> bool:
        if any(fnmatch.fnmatch(tool_name, pattern) for pattern in principal.deny):
            return False
        return any(fnmatch.fnmatch(tool_name, pattern) for pattern in principal.allow)

    def check_call(
        self,
        principal: Principal,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        now: float | None = None,
    ) -> PolicyResult:
        for pattern in principal.deny:
            if fnmatch.fnmatch(tool_name, pattern):
                return PolicyResult(
                    Decision.DENY, f"'{tool_name}' matches deny rule '{pattern}'", pattern
                )

        allowed_by = next(
            (p for p in principal.allow if fnmatch.fnmatch(tool_name, p)),
            None,
        )
        if allowed_by is None:
            return PolicyResult(
                Decision.DENY, f"'{tool_name}' is not in the allow list for {principal.id}"
            )

        for guard in principal.argument_guards:
            violation = guard.check(tool_name, arguments)
            if violation:
                return PolicyResult(Decision.DENY, violation, f"guard:{guard.tool}:{guard.field}")

        for pattern in principal.require_approval:
            if (
                fnmatch.fnmatch(tool_name, pattern)
                and (principal.id, tool_name) not in self._approvals
            ):
                return PolicyResult(
                    Decision.NEEDS_APPROVAL,
                    f"'{tool_name}' requires human approval before it can run",
                    pattern,
                )

        if not self._consume(f"principal:{principal.id}", principal.rate_limit, now):
            return PolicyResult(
                Decision.RATE_LIMITED,
                f"principal '{principal.id}' exceeded "
                f"{principal.rate_limit.calls_per_minute} calls/minute",
            )
        if principal.per_tool_rate_limit is not None:
            key = f"tool:{principal.id}:{tool_name}"
            if not self._consume(key, principal.per_tool_rate_limit, now):
                return PolicyResult(
                    Decision.RATE_LIMITED,
                    f"'{tool_name}' exceeded "
                    f"{principal.per_tool_rate_limit.calls_per_minute} calls/minute "
                    f"for principal '{principal.id}'",
                )
        return PolicyResult(Decision.ALLOW, matched_rule=allowed_by)

    def _consume(self, key: str, limit: RateLimit, now: float | None) -> bool:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = TokenBucket(limit.burst, limit.calls_per_minute)
            self._buckets[key] = bucket
        return bucket.consume(now=now)

    # --- approvals -------------------------------------------------------

    def grant_approval(self, principal_id: str, tool_name: str) -> None:
        self._approvals.add((principal_id, tool_name))

    def revoke_approval(self, principal_id: str, tool_name: str) -> None:
        self._approvals.discard((principal_id, tool_name))

    def pending_approvals(self) -> list[dict[str, str]]:
        return [{"principal": p, "tool": t} for p, t in sorted(self._approvals)]
