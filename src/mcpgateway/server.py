"""HTTP surface: the MCP streamable-HTTP endpoint plus a small admin API."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .config import GatewayConfig
from .gateway import Gateway, Session
from .jsonrpc import UNAUTHORIZED, JsonRpcError, error_response
from .policy import Principal

log = logging.getLogger(__name__)

SESSION_HEADER = "Mcp-Session-Id"


def build_app(config: GatewayConfig) -> FastAPI:
    gateway = Gateway(config)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await gateway.start()
        try:
            yield
        finally:
            await gateway.aclose()

    app = FastAPI(
        title=f"{config.name} admin & MCP endpoint",
        version=config.version,
        lifespan=lifespan,
        docs_url="/docs",
    )
    app.state.gateway = gateway

    # --- auth ------------------------------------------------------------

    def bearer(authorization: str | None) -> str | None:
        if not authorization:
            return None
        scheme, _, token = authorization.partition(" ")
        return token.strip() if scheme.lower() == "bearer" else None

    def authenticate(authorization: str | None) -> Principal:
        if not config.require_auth:
            return gateway.policy.principals.get(
                "anonymous", Principal(id="anonymous", allow=["*"], admin=True)
            )
        principal = gateway.policy.authenticate(bearer(authorization))
        if principal is None:
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")
        return principal

    def require_admin(authorization: str | None = Header(default=None)) -> Principal:
        principal = authenticate(authorization)
        if not principal.admin:
            raise HTTPException(status_code=403, detail="principal is not an administrator")
        return principal

    # --- MCP endpoint ----------------------------------------------------

    @app.post("/mcp")
    async def mcp_endpoint(
        request: Request,
        authorization: str | None = Header(default=None),
        mcp_session_id: str | None = Header(default=None, alias=SESSION_HEADER),
    ) -> Response:
        try:
            principal = authenticate(authorization)
        except HTTPException:
            gateway.audit.write("auth.failed", decision="deny", detail={"path": "/mcp"})
            return JSONResponse(
                status_code=401,
                content=error_response(
                    None, JsonRpcError(UNAUTHORIZED, "invalid or missing bearer token")
                ),
            )

        try:
            payload = json.loads(await request.body())
        except json.JSONDecodeError:
            return JSONResponse(
                status_code=400,
                content=error_response(None, JsonRpcError(-32700, "malformed JSON")),
            )

        session = _resolve_session(gateway, mcp_session_id, principal)

        if isinstance(payload, list):  # JSON-RPC batch
            responses = [r for r in [await gateway.handle(item, session) for item in payload] if r]
            body: Any = responses
        else:
            body = await gateway.handle(payload, session)

        pending = session.drain_notifications()
        headers = {SESSION_HEADER: session.id}

        if body is None and not pending:
            return Response(status_code=202, headers=headers)

        if pending:
            # Streamable HTTP lets one POST return several messages; the
            # list_changed notification has to reach the client so it re-lists
            # tools loaded by gateway__search_tools.
            frames = [*pending] + ([body] if body is not None else [])
            sse = "".join(f"event: message\ndata: {json.dumps(f)}\n\n" for f in frames)
            return Response(
                content=sse,
                media_type="text/event-stream",
                headers={**headers, "Cache-Control": "no-cache"},
            )
        return JSONResponse(content=body, headers=headers)

    @app.delete("/mcp")
    async def end_session(
        mcp_session_id: str | None = Header(default=None, alias=SESSION_HEADER),
    ) -> Response:
        if mcp_session_id:
            gateway.drop_session(mcp_session_id)
        return Response(status_code=204)

    # --- operational endpoints -------------------------------------------

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        unhealthy = [n for n, u in gateway.upstreams.items() if not u.connected]
        return {"status": "degraded" if unhealthy else "ok", "unavailable_upstreams": unhealthy}

    @app.get("/admin/status")
    async def status(_: Principal = Depends(require_admin)) -> dict[str, Any]:
        return gateway.status()

    @app.get("/admin/tools")
    async def list_tools(
        quarantined: bool | None = None, _: Principal = Depends(require_admin)
    ) -> dict[str, Any]:
        entries = gateway.registry.all()
        if quarantined is not None:
            entries = [e for e in entries if e.quarantined is quarantined]
        return {"count": len(entries), "tools": [e.to_dict() for e in entries]}

    @app.get("/admin/findings")
    async def findings(
        min_score: int = 1, _: Principal = Depends(require_admin)
    ) -> dict[str, Any]:
        flagged = [
            e.to_dict() for e in gateway.registry.all() if e.scan.score >= min_score
        ]
        flagged.sort(key=lambda e: -e["scan"]["score"])
        return {"count": len(flagged), "tools": flagged}

    @app.post("/admin/tools/{name}/approve")
    async def approve(
        name: str, note: str = "", principal: Principal = Depends(require_admin)
    ) -> dict[str, Any]:
        try:
            entry = gateway.registry.approve(name, by=principal.id, note=note)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown tool '{name}'") from None
        gateway._rebuild_index()
        gateway.audit.write(
            "tool.approved", principal=principal.id, tool=name, decision="approve",
            detail={"fingerprint": entry.tool.fingerprint, "note": note},
        )
        return entry.to_dict()

    @app.post("/admin/tools/{name}/revoke")
    async def revoke(name: str, principal: Principal = Depends(require_admin)) -> dict[str, Any]:
        entry = gateway.registry.revoke(name)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"unknown tool '{name}'")
        gateway._rebuild_index()
        gateway.audit.write(
            "tool.revoked", principal=principal.id, tool=name, decision="revoke", detail={}
        )
        return entry.to_dict()

    @app.post("/admin/refresh")
    async def refresh(_: Principal = Depends(require_admin)) -> dict[str, Any]:
        return await gateway.refresh()

    @app.get("/admin/audit")
    async def audit_tail(limit: int = 100, _: Principal = Depends(require_admin)) -> dict[str, Any]:
        return {"records": gateway.audit.tail(limit)}

    @app.get("/admin/audit/verify")
    async def audit_verify(_: Principal = Depends(require_admin)) -> dict[str, Any]:
        return gateway.audit.verify()

    @app.post("/admin/approvals/{principal_id}/{tool}")
    async def grant_approval(
        principal_id: str, tool: str, _: Principal = Depends(require_admin)
    ) -> dict[str, Any]:
        gateway.policy.grant_approval(principal_id, tool)
        return {"granted": {"principal": principal_id, "tool": tool}}

    return app


def _resolve_session(gateway: Gateway, session_id: str | None, principal: Principal) -> Session:
    if session_id:
        existing = gateway.sessions.get(session_id)
        # A session belongs to the principal that created it.
        if existing is not None and existing.principal.id == principal.id:
            return existing
    return gateway.create_session(principal)
