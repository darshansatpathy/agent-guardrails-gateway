from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from guardrails_gateway.approvals import ApprovalStore
from guardrails_gateway.audit import AuditLog
from guardrails_gateway.gateway import Gateway
from guardrails_gateway.grants import GrantIssuer
from guardrails_gateway.models import ToolCall
from guardrails_gateway.policy import Policy
from guardrails_gateway.tools import demo_registry

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "support-agent.yaml"
SECRET = b"test-secret-test-secret-test-secret!"

ALL_SUPPORT_TOOLS = ["search_docs", "read_invoice", "web_fetch", "send_email", "refund_payment"]


class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def policy() -> Policy:
    return Policy.from_yaml(POLICY_PATH)


@pytest.fixture
def gateway(tmp_path: Path, policy: Policy, clock: FakeClock) -> Iterator[Gateway]:
    gw = Gateway(
        policy=policy,
        grants=GrantIssuer(SECRET, policy.defaults.max_grant_ttl_seconds, clock=clock),
        audit=AuditLog(tmp_path / "audit.jsonl", key=b"audit-key"),
        approvals=ApprovalStore(tmp_path / "approvals.db", clock=clock),
        registry=demo_registry(),
    )
    yield gw
    gw.close()


@pytest.fixture
def grant(gateway: Gateway) -> str:
    return gateway.issue_grant("support-agent", "T-1", ALL_SUPPORT_TOOLS, 600, "tests")


def make_call(tool: str, session: str = "s1", **arguments: object) -> ToolCall:
    return ToolCall(
        agent_id="support-agent",
        task_id="T-1",
        session_id=session,
        tool=tool,
        arguments=dict(arguments),
    )
