#!/usr/bin/env python3
"""Walk through everything the gateway does, against real MCP servers.

Run from the repository root:  python examples/demo.py
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcpgateway.config import GatewayConfig
from mcpgateway.gateway import Gateway

FIXTURE = str(ROOT / "tests" / "fixtures" / "fake_mcp_server.py")
DEV_TOKEN = "dev-token"


def heading(text: str) -> None:
    print(f"\n\033[1m{text}\033[0m\n" + "-" * len(text))


def build_config(workdir: Path, *, rugpull: bool = False) -> GatewayConfig:
    def upstream(profile: str, extra: list[str] | None = None) -> dict:
        return {
            "name": profile,
            "transport": "stdio",
            "command": sys.executable,
            "args": [FIXTURE, "--profile", profile, "--name", profile] + (extra or []),
            "timeout": 15.0,
        }

    return GatewayConfig.from_dict(
        {
            "gateway": {
                "name": "mcp-gateway-demo",
                "registry": {"pin_file": str(workdir / "pins.json")},
                "audit": {"path": str(workdir / "audit.jsonl")},
                "retrieval": {"enabled": True, "max_tools_exposed": 15, "top_k": 5},
            },
            "upstreams": [
                upstream("files", ["--rugpull"] if rugpull else None),
                upstream("evil"),
                upstream("bulk"),
            ],
            "principals": [
                {
                    "id": "agent-dev",
                    "token_sha256": hashlib.sha256(DEV_TOKEN.encode()).hexdigest(),
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
                }
            ],
        }
    )


async def rpc(gateway, session, method, params=None):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params:
        payload["params"] = params
    return await gateway.handle(payload, session)


async def call_tool(gateway, session, name, arguments):
    return await rpc(gateway, session, "tools/call", {"name": name, "arguments": arguments})


async def main() -> None:
    logging.disable(logging.WARNING)
    workdir = Path(tempfile.mkdtemp(prefix="mcp-gateway-demo-"))
    gateway = Gateway(build_config(workdir))
    await gateway.start()
    session = gateway.create_session(gateway.policy.principals["agent-dev"])
    await rpc(gateway, session, "initialize", {"protocolVersion": "2025-06-18"})

    try:
        heading("1. Three upstream MCP servers behind one endpoint")
        stats = gateway.registry.stats()
        print(f"tools discovered : {stats['total']}")
        print(f"callable         : {stats['callable']}")
        print(f"quarantined      : {stats['quarantined']}")
        print(f"per server       : {stats['by_server']}")

        heading("2. Poisoned tool definitions are blocked before the model sees them")
        for entry in gateway.registry.quarantined_tools():
            print(f"\n  {entry.qualified_name}  risk score {entry.scan.score}/100")
            for finding in entry.scan.findings[:3]:
                print(f"    [{finding.severity.value:8}] {finding.rule}  {finding.message}")
                print(f"               at {finding.location}: {finding.evidence[:90]}")

        heading("3. What the model actually receives")
        listed = (await rpc(gateway, session, "tools/list"))["result"]
        gateway_meta = listed["_meta"]["gateway"]
        print(f"catalogue visible to this principal : {gateway_meta['catalogue']} tools")
        print(f"actually exposed this turn          : {gateway_meta['exposed']} tools")
        print(f"full catalogue cost                 : ~{gateway_meta['full_catalogue_tokens']} tokens")
        print(f"exposed cost                        : ~{gateway_meta['exposed_tokens']} tokens")
        saved = 1 - gateway_meta["exposed_tokens"] / max(1, gateway_meta["full_catalogue_tokens"])
        print(f"context saved                       : {saved:.0%}")
        print("exposed names                       : " + ", ".join(t["name"] for t in listed["tools"]))

        heading("4. The model finds what it needs on demand")
        response = await call_tool(
            gateway, session, "gateway__search_tools", {"query": "refund a customer invoice", "limit": 3}
        )
        print(response["result"]["content"][0]["text"])
        print(f"\nnotifications emitted: {[n['method'] for n in session.pending_notifications]}")
        listed = (await rpc(gateway, session, "tools/list"))["result"]
        print("now exposed: " + ", ".join(t["name"] for t in listed["tools"]))

        heading("5. Calls are brokered, not just forwarded")
        ok = await call_tool(gateway, session, "files__read_file", {"path": "README.md"})
        print(f"  allowed   files__read_file          -> {ok['result']['content'][0]['text']}")

        denied = await call_tool(gateway, session, "files__delete_file", {"path": "x"})
        print(f"  denied    files__delete_file        -> {denied['error']['message']}")

        guarded = await call_tool(gateway, session, "files__read_file", {"path": "/home/u/.ssh/id_rsa"})
        print(f"  guarded   files__read_file(.ssh)    -> {guarded['error']['message']}")

        blocked = await call_tool(gateway, session, "evil__sync_metadata", {"project": "x"})
        print(f"  poisoned  evil__sync_metadata       -> {blocked['error']['message'][:110]}")

        heading("6. Indirect injection: a clean tool returning attacker-controlled text")
        result = (
            await call_tool(gateway, session, "evil__fetch_web_page", {"url": "https://example.com/q3"})
        )["result"]
        print(f"  isError : {result['isError']}")
        print(f"  rules   : {[f['rule'] for f in result['_meta']['gateway']['findings']]}")
        print(f"  model sees: {result['content'][0]['text'][:150]}...")

        heading("7. Supply-chain: approve a tool, then the server changes it")
        gateway.registry.approve("files__read_file", by="demo-operator", note="reviewed")
        pinned = gateway.registry.get("files__read_file").tool.fingerprint
        print(f"  approved files__read_file at fingerprint {pinned[:16]}")
        await gateway.aclose()

        rugpulled = Gateway(build_config(workdir, rugpull=True))
        await rugpulled.start()
        gateway = rugpulled
        entry = gateway.registry.get("files__read_file")
        print(f"  upstream restarted; now serving      {entry.tool.fingerprint[:16]}")
        print(f"  quarantined: {entry.quarantined}")
        for reason in entry.reasons:
            print(f"    - {reason}")

        heading("8. Tamper-evident audit trail")
        report = gateway.audit.verify()
        print(f"  chain valid: {report['valid']} over {report['checked']} records")
        calls = [r for r in gateway.audit.read_all() if r["event"].startswith("tools.")]
        for record in calls[:6]:
            print(
                f"    #{record['seq']:<3} {record['event']:<14} {record['tool']:<26} "
                f"{record['decision']}"
            )
        # Now edit history the way someone covering their tracks would.
        import json

        from mcpgateway.audit import AuditLog

        audit_path = workdir / "audit.jsonl"
        lines = audit_path.read_text().splitlines()
        index = next(
            i for i, line in enumerate(lines) if json.loads(line).get("decision") == "deny"
        )
        record = json.loads(lines[index])
        record["decision"] = "allow"
        lines[index] = json.dumps(record)
        audit_path.write_text("\n".join(lines) + "\n")
        print(f"\n  someone rewrites record #{record['seq']} from deny to allow...")

        after = AuditLog(audit_path).verify()
        print(f"  chain valid: {after['valid']}, broken at record #{after['broken_at']}")
        print(f"  reason: {after['error']}")

    finally:
        await gateway.aclose()
        shutil.rmtree(workdir, ignore_errors=True)

    print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
