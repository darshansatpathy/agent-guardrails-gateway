from __future__ import annotations

import pytest

from guardrails_gateway.gateway import Gateway, redact
from guardrails_gateway.grants import GrantError
from guardrails_gateway.models import Outcome, ToolCall
from tests.conftest import FakeClock, make_call


def _rules(gateway: Gateway) -> list[str]:
    return [r["data"]["rule"] for r in gateway.audit.records() if r["event"] == "decision"]


def test_allowed_call_executes_and_is_audited(gateway: Gateway, grant: str) -> None:
    result = gateway.invoke(make_call("search_docs", query="refunds"), grant)
    assert result.decision.outcome is Outcome.ALLOW
    assert result.result["query"] == "refunds"
    events = [r["event"] for r in gateway.audit.records()]
    assert events[-2:] == ["decision", "tool.result"]
    assert gateway.audit.verify().ok


@pytest.mark.parametrize(
    ("call", "rule"),
    [
        (make_call("delete_record", record_id="C-1"), "grant.tool_out_of_scope"),
        (make_call("read_invoice", invoice_id="1001"), "policy.argument_violation"),
        (make_call("read_invoice", invoice_id="INV-1001", fields="*"), "policy.argument_violation"),
        (make_call("send_email", to="x@evil.test", subject="hi"), "policy.argument_violation"),
        (
            make_call("refund_payment", invoice_id="INV-1001", amount=900, currency="USD"),
            "policy.argument_violation",
        ),
    ],
)
def test_denials(gateway: Gateway, grant: str, call: ToolCall, rule: str) -> None:
    decision = gateway.evaluate(call, grant)
    assert decision.outcome is Outcome.DENY
    assert decision.rule == rule


def test_grant_for_another_agent_or_task_is_denied(gateway: Gateway, grant: str) -> None:
    other_agent = make_call("search_docs", query="q").model_copy(update={"agent_id": "intruder"})
    other_task = make_call("search_docs", query="q").model_copy(update={"task_id": "T-2"})
    assert gateway.evaluate(other_agent, grant).rule == "grant.wrong_agent"
    assert gateway.evaluate(other_task, grant).rule == "grant.wrong_task"


def test_agent_without_permission_is_denied_even_with_a_valid_grant(gateway: Gateway) -> None:
    token = gateway.grants.issue("analytics-agent", "T-9", ["send_email"], 60)
    call = ToolCall(
        agent_id="analytics-agent",
        task_id="T-9",
        session_id="s",
        tool="send_email",
        arguments={"to": "a@example.com", "subject": "s"},
    )
    assert gateway.evaluate(call, token).rule == "policy.not_permitted"


def test_grant_cannot_exceed_policy(gateway: Gateway) -> None:
    with pytest.raises(GrantError, match="does not allow"):
        gateway.issue_grant("support-agent", "T-3", ["delete_record"], 60, "tests")


def test_expired_grant_is_denied(gateway: Gateway, grant: str, clock: FakeClock) -> None:
    clock.advance(601)
    assert gateway.evaluate(make_call("search_docs", query="q"), grant).rule == "grant.invalid"


def test_high_risk_requires_approval_then_runs_once(gateway: Gateway, grant: str) -> None:
    call = make_call("refund_payment", invoice_id="INV-1001", amount=120, currency="USD")
    first = gateway.invoke(call, grant)
    assert first.decision.outcome is Outcome.REQUIRE_APPROVAL
    assert first.result is None
    assert first.decision.approval_id

    gateway.decide_approval(first.decision.approval_id, True, decided_by="finance-lead")
    second = gateway.invoke(call, grant)
    assert second.decision.rule == "approval.granted"
    assert second.result["status"] == "refunded"

    third = gateway.invoke(call, grant)
    assert third.decision.outcome is Outcome.REQUIRE_APPROVAL


def test_taint_gates_egress_after_untrusted_read(gateway: Gateway, grant: str) -> None:
    email = make_call("send_email", session="s9", to="a@example.com", subject="hi")
    assert gateway.evaluate(email, grant).outcome is Outcome.ALLOW

    gateway.invoke(make_call("web_fetch", session="s9", url="https://example.org"), grant)
    gated = gateway.evaluate(email, grant)
    assert gated.outcome is Outcome.REQUIRE_APPROVAL
    assert "untrusted content" in gated.reason

    other_session = make_call("send_email", session="s10", to="a@example.com", subject="hi")
    assert gateway.evaluate(other_session, grant).outcome is Outcome.ALLOW


def test_rate_limit(gateway: Gateway, grant: str) -> None:
    for i in range(5):
        call = make_call("send_email", session=f"r{i}", to="a@example.com", subject=str(i))
        assert gateway.evaluate(call, grant).outcome is Outcome.ALLOW
    sixth = make_call("send_email", session="r6", to="a@example.com", subject="6")
    assert gateway.evaluate(sixth, grant).rule == "rate_limit.exceeded"


def test_revoked_task_is_denied(gateway: Gateway, grant: str) -> None:
    gateway.revoke_task("T-1", revoked_by="oncall")
    assert gateway.evaluate(make_call("search_docs", query="q"), grant).rule == "grant.invalid"


def test_tool_errors_are_contained_and_audited(gateway: Gateway, grant: str) -> None:
    result = gateway.invoke(make_call("search_docs", query="q", unexpected="arg"), grant)
    assert result.decision.outcome is Outcome.ALLOW
    assert result.error and "TypeError" in result.error
    last = gateway.audit.records()[-1]
    assert last["event"] == "tool.result" and last["data"]["ok"] is False


def test_sensitive_arguments_are_redacted() -> None:
    masked = redact({"api_key": "sk-123", "card_number": "4111", "amount": 5})
    assert masked == {"api_key": "***", "card_number": "***", "amount": 5}


def test_every_decision_is_audited(gateway: Gateway, grant: str) -> None:
    gateway.evaluate(make_call("search_docs", query="q"), grant)
    gateway.evaluate(make_call("delete_record", record_id="x"), grant)
    assert _rules(gateway) == ["allow", "grant.tool_out_of_scope"]
    assert gateway.metrics["decision.allow"] == 1
    assert gateway.metrics["decision.deny"] == 1
