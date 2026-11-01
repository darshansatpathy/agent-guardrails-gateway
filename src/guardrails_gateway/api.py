"""HTTP API.

Two audiences, two credentials:
- Agents call POST /v1/tool-calls with their task grant in `X-Agent-Grant`.
- Operators (orchestrator, reviewers, auditors) use the admin bearer token for grants,
  approvals and audit endpoints. In production this would sit behind your SSO/OIDC.
"""

from __future__ import annotations

import hmac
import re
import uuid
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from guardrails_gateway import __version__
from guardrails_gateway.approvals import ApprovalError, ApprovalStatus
from guardrails_gateway.config import Settings, build_gateway
from guardrails_gateway.gateway import Gateway
from guardrails_gateway.grants import GrantError
from guardrails_gateway.models import ToolCall
from guardrails_gateway.observability import configure_logging, request_id_var

_SAFE_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")


class GrantRequest(BaseModel):
    agent_id: str
    task_id: str
    tools: list[str] = Field(min_length=1)
    ttl_seconds: int = Field(default=900, gt=0)
    issued_by: str


class ApprovalDecision(BaseModel):
    decided_by: str = Field(min_length=1)
    note: str = ""


class RevokeRequest(BaseModel):
    revoked_by: str = Field(min_length=1)


def create_app(gateway: Gateway, admin_token: str) -> FastAPI:
    app = FastAPI(
        title="Agent Guardrails Gateway",
        version=__version__,
        description="Policy enforcement point between AI agents and their tools.",
    )

    @app.middleware("http")
    async def request_id(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-request-id", "")
        rid = incoming if _SAFE_REQUEST_ID.fullmatch(incoming) else uuid.uuid4().hex
        token = request_id_var.set(rid)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = rid
        return response

    def require_admin(authorization: Annotated[str | None, Header()] = None) -> None:
        expected = f"Bearer {admin_token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "admin token required")

    admin = [Depends(require_admin)]

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/v1/tool-calls")
    def tool_call(call: ToolCall, x_agent_grant: Annotated[str, Header()]) -> dict[str, Any]:
        outcome = gateway.invoke(call, x_agent_grant)
        body: dict[str, Any] = {"decision": outcome.decision.model_dump()}
        if outcome.result is not None:
            body["result"] = outcome.result
        if outcome.error:
            body["error"] = outcome.error
        return body

    @app.post("/v1/grants", dependencies=admin)
    def issue_grant(req: GrantRequest) -> dict[str, str]:
        try:
            token = gateway.issue_grant(
                req.agent_id, req.task_id, req.tools, req.ttl_seconds, req.issued_by
            )
        except GrantError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        return {"grant": token}

    @app.post("/v1/tasks/{task_id}/revoke", dependencies=admin)
    def revoke_task(task_id: str, req: RevokeRequest) -> dict[str, str]:
        gateway.revoke_task(task_id, req.revoked_by)
        return {"status": "revoked", "task_id": task_id}

    @app.get("/v1/approvals", dependencies=admin)
    def list_approvals(status_filter: ApprovalStatus | None = None) -> list[dict[str, Any]]:
        return [a.to_dict() for a in gateway.approvals.list(status_filter)]

    @app.post("/v1/approvals/{approval_id}/approve", dependencies=admin)
    def approve(approval_id: str, req: ApprovalDecision) -> dict[str, Any]:
        return _decide(approval_id, True, req)

    @app.post("/v1/approvals/{approval_id}/deny", dependencies=admin)
    def deny(approval_id: str, req: ApprovalDecision) -> dict[str, Any]:
        return _decide(approval_id, False, req)

    def _decide(approval_id: str, approve: bool, req: ApprovalDecision) -> dict[str, Any]:
        try:
            return gateway.decide_approval(approval_id, approve, req.decided_by, req.note)
        except ApprovalError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    @app.get("/v1/audit/verify", dependencies=admin)
    def verify_audit() -> dict[str, Any]:
        result = gateway.audit.verify()
        return {
            "ok": result.ok,
            "records": result.records,
            "head": result.head,
            "first_bad_seq": result.first_bad_seq,
            "reason": result.reason,
        }

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics() -> str:
        lines = ["# TYPE aggw_events_total counter"]
        for key, value in sorted(gateway.metrics.items()):
            lines.append(f'aggw_events_total{{event="{key}"}} {value}')
        return "\n".join(lines) + "\n"

    return app


def app_from_env() -> FastAPI:
    """Entry point for `uvicorn guardrails_gateway.api:app_from_env --factory`."""
    configure_logging()
    settings = Settings.from_env()
    return create_app(build_gateway(settings), settings.admin_token)
