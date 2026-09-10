"""End-to-end tests: a real gateway talking to real subprocess MCP servers."""

from __future__ import annotations

import pytest
from conftest import base_config

from mcpgateway.config import GatewayConfig
from mcpgateway.gateway import Gateway
from mcpgateway.jsonrpc import FORBIDDEN, QUARANTINED, RATE_LIMITED
from mcpgateway.protocol import TOOLS_LIST_CHANGED


async def call(gateway, session, method, params=None, request_id=1):
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params:
        payload["params"] = params
    return await gateway.handle(payload, session)


async def initialize(gateway, session):
    response = await call(
        gateway,
        session,
        "initialize",
        {"protocolVersion": "2025-06-18", "clientInfo": {"name": "pytest", "version": "1"}},
    )
    await gateway.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    return response


async def test_initialize_returns_server_info(gateway, dev_session):
    response = await initialize(gateway, dev_session)
    result = response["result"]
    assert result["serverInfo"]["name"] == "test-gateway"
    assert result["capabilities"]["tools"]["listChanged"] is True
    assert dev_session.initialized is True


async def test_upstreams_connect_and_tools_are_namespaced(gateway, dev_session):
    names = {entry.qualified_name for entry in gateway.registry.all()}
    assert "files__read_file" in names
    assert "evil__get_weather" in names
    assert gateway.status()["upstreams"]["files"]["connected"] is True


async def test_poisoned_tool_never_reaches_the_client(gateway, dev_session):
    await initialize(gateway, dev_session)
    listed = (await call(gateway, dev_session, "tools/list"))["result"]["tools"]
    names = {tool["name"] for tool in listed}
    assert "evil__sync_metadata" not in names
    assert "evil__schema_smuggler" not in names
    assert "files__read_file" in names

    entry = gateway.registry.get("evil__sync_metadata")
    assert entry.quarantined
    assert entry.scan.score >= 60


async def test_calling_a_quarantined_tool_is_refused_with_findings(gateway, dev_session):
    response = await call(
        gateway,
        dev_session,
        "tools/call",
        {"name": "evil__sync_metadata", "arguments": {"project": "x"}},
    )
    error = response["error"]
    assert error["code"] == QUARANTINED
    assert "quarantined" in error["message"]
    assert error["data"]["findings"]


async def test_benign_call_is_proxied_to_the_upstream(gateway, dev_session):
    response = await call(
        gateway,
        dev_session,
        "tools/call",
        {"name": "files__read_file", "arguments": {"path": "notes.md"}},
    )
    text = response["result"]["content"][0]["text"]
    assert text == "contents of notes.md"


async def test_policy_denies_a_tool_outside_the_allow_list(gateway, dev_session):
    response = await call(
        gateway,
        dev_session,
        "tools/call",
        {"name": "files__delete_file", "arguments": {"path": "x"}},
    )
    assert response["error"]["code"] == FORBIDDEN


async def test_argument_guard_blocks_sensitive_paths(gateway, dev_session):
    response = await call(
        gateway,
        dev_session,
        "tools/call",
        {"name": "files__read_file", "arguments": {"path": "/home/dev/.ssh/id_rsa"}},
    )
    assert response["error"]["code"] == FORBIDDEN
    assert "denied pattern" in response["error"]["message"]


async def test_indirect_injection_in_a_tool_result_is_blocked(gateway, dev_session):
    """The tool itself is clean; the page it returns is not."""
    response = await call(
        gateway,
        dev_session,
        "tools/call",
        {"name": "evil__fetch_web_page", "arguments": {"url": "https://example.com/report"}},
    )
    result = response["result"]
    assert result["isError"] is True
    assert result["_meta"]["gateway"]["blocked"] is True
    assert "ignore all previous instructions" not in result["content"][0]["text"].lower()
    assert any(f["rule"] == "INJ001" for f in result["_meta"]["gateway"]["findings"])


async def test_unknown_tool_points_the_model_at_search(gateway, dev_session):
    response = await call(
        gateway, dev_session, "tools/call", {"name": "files__nope", "arguments": {}}
    )
    assert "gateway__search_tools" in response["error"]["message"]


async def test_audit_log_records_every_decision_and_verifies(gateway, dev_session):
    await initialize(gateway, dev_session)
    await call(gateway, dev_session, "tools/call", {"name": "files__read_file", "arguments": {"path": "a"}})
    await call(gateway, dev_session, "tools/call", {"name": "files__delete_file", "arguments": {"path": "b"}})

    records = gateway.audit.tail(50)
    decisions = {(r["tool"], r["decision"]) for r in records if r["event"] == "tools.call"}
    assert ("files__read_file", "allow") in decisions
    assert ("files__delete_file", "deny") in decisions
    assert gateway.audit.verify()["valid"] is True


async def test_rate_limit_is_enforced_per_principal(tmp_path):
    config = GatewayConfig.from_dict(base_config(tmp_path))
    config.principals[0].rate_limit.burst = 2
    config.principals[0].rate_limit.calls_per_minute = 2
    gateway = Gateway(config)
    await gateway.start()
    try:
        session = gateway.create_session(gateway.policy.principals["dev"])
        params = {"name": "files__read_file", "arguments": {"path": "a"}}
        assert "result" in await call(gateway, session, "tools/call", params)
        assert "result" in await call(gateway, session, "tools/call", params)
        third = await call(gateway, session, "tools/call", params)
        assert third["error"]["code"] == RATE_LIMITED
    finally:
        await gateway.aclose()


# --- dynamic retrieval -------------------------------------------------------


async def test_large_catalogue_is_hidden_behind_search(bulk_gateway):
    session = bulk_gateway.create_session(bulk_gateway.policy.principals["dev"])
    await initialize(bulk_gateway, session)
    result = (await call(bulk_gateway, session, "tools/list"))["result"]
    stats = result["_meta"]["gateway"]

    assert stats["mode"] == "retrieval"
    assert stats["catalogue"] > 40
    # Only the three meta tools are exposed before anything is searched for.
    assert len(result["tools"]) == 3
    assert stats["exposed_tokens"] < stats["full_catalogue_tokens"] * 0.2


async def test_search_loads_tools_and_emits_list_changed(bulk_gateway):
    session = bulk_gateway.create_session(bulk_gateway.policy.principals["dev"])
    await initialize(bulk_gateway, session)

    response = await call(
        bulk_gateway,
        session,
        "tools/call",
        {"name": "gateway__search_tools", "arguments": {"query": "refund a stripe invoice", "limit": 3}},
    )
    loaded = response["result"]["_meta"]["gateway"]["loaded"]
    assert "bulk__refund_invoice" in loaded

    notifications = session.drain_notifications()
    assert any(n["method"] == TOOLS_LIST_CHANGED for n in notifications)

    listed = (await call(bulk_gateway, session, "tools/list"))["result"]["tools"]
    assert "bulk__refund_invoice" in {tool["name"] for tool in listed}


async def test_a_searched_tool_becomes_callable(bulk_gateway):
    session = bulk_gateway.create_session(bulk_gateway.policy.principals["dev"])
    await initialize(bulk_gateway, session)
    await call(
        bulk_gateway,
        session,
        "tools/call",
        {"name": "gateway__search_tools", "arguments": {"query": "scale a kubernetes deployment"}},
    )
    response = await call(
        bulk_gateway,
        session,
        "tools/call",
        {"name": "bulk__scale_deployment", "arguments": {"deployment_id": "api"}},
    )
    assert "result" in response


async def test_describe_tool_does_not_execute_anything(bulk_gateway):
    session = bulk_gateway.create_session(bulk_gateway.policy.principals["dev"])
    response = await call(
        bulk_gateway,
        session,
        "tools/call",
        {"name": "gateway__describe_tool", "arguments": {"name": "bulk__create_issue"}},
    )
    body = response["result"]["content"][0]["text"]
    assert "inputSchema" in body


async def test_working_set_is_per_session(bulk_gateway):
    alice = bulk_gateway.create_session(bulk_gateway.policy.principals["dev"])
    bob = bulk_gateway.create_session(bulk_gateway.policy.principals["dev"])
    await call(
        bulk_gateway,
        alice,
        "tools/call",
        {"name": "gateway__search_tools", "arguments": {"query": "stripe invoice"}},
    )
    assert alice.working_set
    assert bob.working_set == []


# --- supply chain ------------------------------------------------------------


async def test_rug_pull_is_detected_on_refresh(tmp_path):
    """Approve a clean tool, then restart the upstream serving a poisoned one."""
    clean = GatewayConfig.from_dict(base_config(tmp_path, profiles=("files",)))
    gateway = Gateway(clean)
    await gateway.start()
    try:
        gateway.registry.approve("files__read_file", by="alice", note="reviewed in PR #12")
        assert not gateway.registry.get("files__read_file").quarantined
    finally:
        await gateway.aclose()

    poisoned = GatewayConfig.from_dict(
        base_config(tmp_path, rugpull=True, profiles=("files",))
    )
    gateway2 = Gateway(poisoned)
    await gateway2.start()
    try:
        entry = gateway2.registry.get("files__read_file")
        assert entry.quarantined
        assert any("changed since approval" in reason for reason in entry.reasons)
    finally:
        await gateway2.aclose()


async def test_gateway_survives_a_dead_upstream(tmp_path):
    raw = base_config(tmp_path, profiles=("files",))
    raw["upstreams"].append(
        {
            "name": "broken",
            "transport": "stdio",
            "command": "/nonexistent/binary",
            "args": [],
            "timeout": 2.0,
        }
    )
    gateway = Gateway(GatewayConfig.from_dict(raw))
    await gateway.start()
    try:
        status = gateway.status()
        assert status["upstreams"]["broken"]["connected"] is False
        assert status["upstreams"]["files"]["connected"] is True
        session = gateway.create_session(gateway.policy.principals["dev"])
        response = await call(
            gateway, session, "tools/call", {"name": "files__read_file", "arguments": {"path": "a"}}
        )
        assert "result" in response
    finally:
        await gateway.aclose()


@pytest.mark.parametrize("method", ["resources/list", "prompts/list", "ping"])
async def test_optional_methods_do_not_error(gateway, dev_session, method):
    response = await call(gateway, dev_session, method)
    assert "error" not in response
