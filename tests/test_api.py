from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from guardrails_gateway.api import create_app
from guardrails_gateway.gateway import Gateway

ADMIN = {"Authorization": "Bearer admin-token"}


@pytest.fixture
def client(gateway: Gateway) -> TestClient:
    return TestClient(create_app(gateway, "admin-token"))


def _grant(client: TestClient) -> str:
    resp = client.post(
        "/v1/grants",
        headers=ADMIN,
        json={
            "agent_id": "support-agent",
            "task_id": "T-1",
            "tools": ["search_docs", "refund_payment"],
            "ttl_seconds": 300,
            "issued_by": "orchestrator",
        },
    )
    assert resp.status_code == 200
    return str(resp.json()["grant"])


def _call(tool: str, **arguments: object) -> dict[str, object]:
    return {
        "agent_id": "support-agent",
        "task_id": "T-1",
        "session_id": "s1",
        "tool": tool,
        "arguments": arguments,
    }


def test_health(client: TestClient) -> None:
    assert client.get("/healthz").json()["status"] == "ok"


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/v1/grants"),
        ("get", "/v1/approvals"),
        ("get", "/v1/audit/verify"),
        ("post", "/v1/approvals/apr_x/approve"),
        ("post", "/v1/tasks/T-1/revoke"),
    ],
)
def test_admin_endpoints_require_token(client: TestClient, method: str, path: str) -> None:
    resp = client.request(method.upper(), path, headers={"Authorization": "Bearer wrong"}, json={})
    assert resp.status_code == 401


def test_full_approval_flow_over_http(client: TestClient) -> None:
    grant = _grant(client)
    headers = {"X-Agent-Grant": grant}

    ok = client.post("/v1/tool-calls", headers=headers, json=_call("search_docs", query="q"))
    assert ok.json()["decision"]["outcome"] == "allow"
    assert "result" in ok.json()

    refund = _call("refund_payment", invoice_id="INV-1001", amount=50, currency="USD")
    pending = client.post("/v1/tool-calls", headers=headers, json=refund).json()
    assert pending["decision"]["outcome"] == "require_approval"
    approval_id = pending["decision"]["approval_id"]

    listed = client.get("/v1/approvals", headers=ADMIN).json()
    assert [a["approval_id"] for a in listed] == [approval_id]

    self_approve = client.post(
        f"/v1/approvals/{approval_id}/approve",
        headers=ADMIN,
        json={"decided_by": "support-agent"},
    )
    assert self_approve.status_code == 409

    approved = client.post(
        f"/v1/approvals/{approval_id}/approve",
        headers=ADMIN,
        json={"decided_by": "finance-lead", "note": "ok"},
    )
    assert approved.json()["status"] == "approved"

    done = client.post("/v1/tool-calls", headers=headers, json=refund).json()
    assert done["decision"]["rule"] == "approval.granted"
    assert done["result"]["status"] == "refunded"

    audit = client.get("/v1/audit/verify", headers=ADMIN).json()
    assert audit["ok"] is True and audit["records"] > 0

    metrics = client.get("/metrics").text
    assert 'aggw_events_total{event="decision.allow"}' in metrics


def test_grant_outside_policy_is_400(client: TestClient) -> None:
    resp = client.post(
        "/v1/grants",
        headers=ADMIN,
        json={
            "agent_id": "support-agent",
            "task_id": "T-1",
            "tools": ["delete_record"],
            "issued_by": "orchestrator",
        },
    )
    assert resp.status_code == 400


def test_missing_grant_header_is_422(client: TestClient) -> None:
    assert client.post("/v1/tool-calls", json=_call("search_docs", query="q")).status_code == 422


def test_revoke_endpoint(client: TestClient) -> None:
    grant = _grant(client)
    client.post("/v1/tasks/T-1/revoke", headers=ADMIN, json={"revoked_by": "oncall"})
    resp = client.post(
        "/v1/tool-calls", headers={"X-Agent-Grant": grant}, json=_call("search_docs", query="q")
    )
    assert resp.json()["decision"]["rule"] == "grant.invalid"
