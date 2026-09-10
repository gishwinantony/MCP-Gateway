"""Configuration model and YAML loader."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .policy import ArgumentGuard, Principal, RateLimit

ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(ValueError):
    pass


def expand_env(value: Any) -> Any:
    """Expand ${VAR} and ${VAR:-default} inside strings, recursively."""
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            name, default = match.group(1), match.group(2)
            resolved = os.environ.get(name)
            if resolved is None:
                if default is None:
                    raise ConfigError(f"environment variable '{name}' is not set")
                return default
            return resolved

        return ENV_PATTERN.sub(replace, value)
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value


@dataclass(slots=True)
class UpstreamConfig:
    name: str
    transport: str = "stdio"
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    inherit_env: bool = False
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0
    verify_tls: bool = True
    enabled: bool = True

    def validate(self) -> None:
        if self.transport == "stdio" and not self.command:
            raise ConfigError(f"upstream '{self.name}': stdio transport needs 'command'")
        if self.transport == "http" and not self.url:
            raise ConfigError(f"upstream '{self.name}': http transport needs 'url'")
        if self.transport not in {"stdio", "http"}:
            raise ConfigError(f"upstream '{self.name}': unknown transport '{self.transport}'")


@dataclass(slots=True)
class ScannerConfig:
    warn_threshold: int = 25
    quarantine_threshold: int = 60
    disabled_rules: list[str] = field(default_factory=list)
    scan_tool_results: bool = True


@dataclass(slots=True)
class RegistryConfig:
    pin_file: str | None = "data/pins.json"
    require_pin: bool = False
    quarantine_on_warn: bool = False
    refresh_interval_seconds: int = 0  # 0 disables periodic refresh


@dataclass(slots=True)
class RetrievalConfig:
    enabled: bool = True
    max_tools_exposed: int = 20
    top_k: int = 8
    always_expose: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AuditConfig:
    path: str | None = "data/audit.jsonl"
    redact_arguments: bool = True


@dataclass(slots=True)
class GatewayConfig:
    name: str = "mcp-gateway"
    version: str = "0.1.0"
    host: str = "127.0.0.1"
    port: int = 8080
    require_auth: bool = True
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    registry: RegistryConfig = field(default_factory=RegistryConfig)
    retrieval: RetrievalConfig = field(default_factory=RetrievalConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    upstreams: list[UpstreamConfig] = field(default_factory=list)
    principals: list[Principal] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, base_dir: Path | None = None) -> GatewayConfig:
        raw = expand_env(raw)
        gateway_section = raw.get("gateway", {}) or {}

        config = cls(
            name=gateway_section.get("name", "mcp-gateway"),
            version=gateway_section.get("version", "0.1.0"),
            host=gateway_section.get("host", "127.0.0.1"),
            port=int(gateway_section.get("port", 8080)),
            require_auth=bool(gateway_section.get("require_auth", True)),
            scanner=_build(ScannerConfig, gateway_section.get("scanner")),
            registry=_build(RegistryConfig, gateway_section.get("registry")),
            retrieval=_build(RetrievalConfig, gateway_section.get("retrieval")),
            audit=_build(AuditConfig, gateway_section.get("audit")),
        )

        for entry in raw.get("upstreams", []) or []:
            upstream = _build(UpstreamConfig, entry)
            upstream.validate()
            config.upstreams.append(upstream)

        principals_raw = raw.get("principals")
        policy_file = raw.get("policy_file")
        if policy_file:
            path = Path(policy_file)
            if base_dir and not path.is_absolute():
                path = base_dir / path
            loaded = expand_env(yaml.safe_load(path.read_text("utf-8")) or {})
            principals_raw = loaded.get("principals", [])
        for entry in principals_raw or []:
            config.principals.append(_build_principal(entry))

        names = [u.name for u in config.upstreams]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise ConfigError(f"duplicate upstream names: {sorted(duplicates)}")
        return config

    @classmethod
    def load(cls, path: str | Path) -> GatewayConfig:
        path = Path(path)
        raw = yaml.safe_load(path.read_text("utf-8")) or {}
        return cls.from_dict(raw, base_dir=path.parent)


def _build(cls: type, data: dict[str, Any] | None):
    """Instantiate a dataclass from a dict, ignoring unknown keys loudly."""
    data = data or {}
    fields = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
    unknown = set(data) - fields
    if unknown:
        raise ConfigError(f"unknown keys for {cls.__name__}: {sorted(unknown)}")
    return cls(**data)


def _build_principal(entry: dict[str, Any]) -> Principal:
    entry = dict(entry)
    token = entry.pop("token", None)
    if token and not entry.get("token_sha256"):
        import hashlib

        entry["token_sha256"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
    rate = entry.pop("rate_limit", None)
    per_tool = entry.pop("per_tool_rate_limit", None)
    guards = entry.pop("argument_guards", []) or []
    principal = Principal(
        **{k: v for k, v in entry.items() if k in Principal.__dataclass_fields__}
    )
    if rate:
        principal.rate_limit = RateLimit(**rate)
    if per_tool:
        principal.per_tool_rate_limit = RateLimit(**per_tool)
    principal.argument_guards = [ArgumentGuard(**g) for g in guards]
    unknown = set(entry) - set(Principal.__dataclass_fields__)
    if unknown:
        raise ConfigError(f"unknown keys for principal '{principal.id}': {sorted(unknown)}")
    return principal
