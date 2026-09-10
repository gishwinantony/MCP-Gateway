from __future__ import annotations

import json

import pytest
from conftest import ADMIN_TOKEN, DEV_TOKEN, base_config
from fastapi.testclient import TestClient

from mcpgateway.config import GatewayConfig
from mcpgateway.server import build_app


@pytest.fixture
def client(tmp_path):
    app = build_app(GatewayConfig.from_dict(base_config(tmp_path)))
    with TestClient(app) as test_client:
        yield test_client


def rpc(client, method, params=None, token=DEV_TOKEN, session=None, request_id=1):
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params:
        payload["params"] = params
    headers = {"Authorization": f"Bearer {token}"}
    if session:
        headers["Mcp-Session-Id"] = session
    return client.post("/mcp", json=payload, headers=headers)


def test_healthz_is_open(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_mcp_requires_a_valid_token(client):
    unauthenticated = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert unauthenticated.status_code == 401
    assert unauthenticated.json()["error"]["code"] == -32001

    wrong = rpc(client, "ping", token="not-a-token")
    assert wrong.status_code == 401


def test_session_id_is_issued_and_reused(client):
    first = rpc(client, "initialize", {"protocolVersion": "2025-06-18"})
    session_id = first.headers["Mcp-Session-Id"]
    assert session_id

    second = rpc(client, "tools/list", session=session_id)
    assert second.headers["Mcp-Session-Id"] == session_id


def test_tools_list_over_http_hides_poisoned_tools(client):
    response = rpc(client, "tools/list")
    names = {tool["name"] for tool in response.json()["result"]["tools"]}
    assert "files__read_file" in names
    assert "evil__sync_metadata" not in names


def test_notifications_return_202(client):
    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers={"Authorization": f"Bearer {DEV_TOKEN}"},
    )
    assert response.status_code == 202


def test_batch_requests_are_supported(client):
    payload = [
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    response = client.post(
        "/mcp", json=payload, headers={"Authorization": f"Bearer {DEV_TOKEN}"}
    )
    body = response.json()
    assert isinstance(body, list) and len(body) == 2
    assert {item["id"] for item in body} == {1, 2}


def test_search_returns_sse_with_list_changed_notification(tmp_path):
    app = build_app(GatewayConfig.from_dict(base_config(tmp_path, profiles=("bulk",))))
    with TestClient(app) as client:
        response = rpc(
            client,
            "tools/call",
            {"name": "gateway__search_tools", "arguments": {"query": "refund a stripe invoice"}},
        )
        assert response.headers["content-type"].startswith("text/event-stream")
        frames = [
            json.loads(line[len("data: ") :])
            for line in response.text.splitlines()
            if line.startswith("data: ")
        ]
        methods = [f.get("method") for f in frames]
        assert "notifications/tools/list_changed" in methods
        assert any("result" in f for f in frames)


def test_admin_endpoints_reject_non_admins(client):
    assert client.get("/admin/status", headers={"Authorization": f"Bearer {DEV_TOKEN}"}).status_code == 403
    assert client.get("/admin/status").status_code == 401


def test_admin_can_inspect_findings_and_approve(client):
    admin = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

    findings = client.get("/admin/findings", headers=admin).json()
    flagged = {tool["name"] for tool in findings["tools"]}
    assert "evil__sync_metadata" in flagged

    quarantined = client.get("/admin/tools?quarantined=true", headers=admin).json()
    assert quarantined["count"] >= 2

    approved = client.post("/admin/tools/evil__sync_metadata/approve?note=reviewed", headers=admin)
    assert approved.status_code == 200
    assert approved.json()["quarantined"] is False

    # It is now callable, and the approval is in the audit trail.
    listed = rpc(client, "tools/list").json()["result"]["tools"]
    assert "evil__sync_metadata" in {tool["name"] for tool in listed}

    audit = client.get("/admin/audit", headers=admin).json()["records"]
    assert any(record["event"] == "tool.approved" for record in audit)


def test_revoke_puts_a_tool_back_in_quarantine(client):
    admin = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    client.post("/admin/tools/evil__sync_metadata/approve", headers=admin)
    revoked = client.post("/admin/tools/evil__sync_metadata/revoke", headers=admin)
    assert revoked.json()["quarantined"] is True


def test_audit_chain_verifies_over_http(client):
    admin = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    rpc(client, "tools/call", {"name": "files__read_file", "arguments": {"path": "a"}})
    report = client.get("/admin/audit/verify", headers=admin).json()
    assert report["valid"] is True
    assert report["checked"] > 0


def test_refresh_rescans_upstreams(client):
    admin = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    response = client.post("/admin/refresh", headers=admin)
    assert response.status_code == 200
    assert response.json()["files"]["tools"] == 4


def test_malformed_json_is_rejected_cleanly(client):
    response = client.post(
        "/mcp",
        content=b"{not json",
        headers={"Authorization": f"Bearer {DEV_TOKEN}", "Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32700
