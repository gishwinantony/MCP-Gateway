from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from mcpgateway.config import GatewayConfig
from mcpgateway.gateway import Gateway

FIXTURE_SERVER = str(Path(__file__).parent / "fixtures" / "fake_mcp_server.py")

DEV_TOKEN = "dev-token"
ADMIN_TOKEN = "admin-token"


def sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def base_config(tmp_path: Path, *, rugpull: bool = False, profiles=("files", "evil")) -> dict:
    upstreams = []
    for profile in profiles:
        args = [FIXTURE_SERVER, "--profile", profile, "--name", profile]
        if rugpull and profile == "files":
            args.append("--rugpull")
        upstreams.append(
            {
                "name": profile,
                "transport": "stdio",
                "command": sys.executable,
                "args": args,
                "timeout": 15.0,
            }
        )
    return {
        "gateway": {
            "name": "test-gateway",
            "require_auth": True,
            "registry": {"pin_file": str(tmp_path / "pins.json")},
            "audit": {"path": str(tmp_path / "audit.jsonl")},
            "retrieval": {"enabled": True, "max_tools_exposed": 20, "top_k": 5},
        },
        "upstreams": upstreams,
        "principals": [
            {
                "id": "dev",
                "token": DEV_TOKEN,
                "allow": ["files__*", "evil__*", "bulk__*", "gateway__*"],
                "deny": ["files__delete_file"],
                "rate_limit": {"calls_per_minute": 600, "burst": 50},
                "argument_guards": [
                    {
                        "tool": "files__read_file",
                        "field": "path",
                        "deny_regex": r"(^|/)\.env$|/\.ssh/",
                    }
                ],
            },
            {
                "id": "admin",
                "token": ADMIN_TOKEN,
                "allow": ["*"],
                "admin": True,
                "rate_limit": {"calls_per_minute": 600, "burst": 50},
            },
        ],
    }


@pytest.fixture
async def gateway(tmp_path):
    config = GatewayConfig.from_dict(base_config(tmp_path))
    gw = Gateway(config)
    await gw.start()
    try:
        yield gw
    finally:
        await gw.aclose()


@pytest.fixture
async def bulk_gateway(tmp_path):
    config = GatewayConfig.from_dict(base_config(tmp_path, profiles=("bulk",)))
    gw = Gateway(config)
    await gw.start()
    try:
        yield gw
    finally:
        await gw.aclose()


@pytest.fixture
def dev_session(gateway):
    principal = gateway.policy.principals["dev"]
    return gateway.create_session(principal)
