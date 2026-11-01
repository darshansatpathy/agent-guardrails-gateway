from __future__ import annotations

import pytest
from pydantic import ValidationError

from guardrails_gateway.policy import AgentToolPolicy, ArgConstraint, Policy
from tests.conftest import POLICY_PATH


def test_example_policy_loads() -> None:
    policy = Policy.from_yaml(POLICY_PATH)
    assert "delete_record" in policy.tools
    assert "delete_record" not in policy.tools_for("support-agent")
    assert policy.tools["refund_payment"].needs_human
    assert policy.tools["web_fetch"].untrusted_output
    assert policy.tools["send_email"].egress


@pytest.mark.parametrize(
    ("constraint", "value", "ok"),
    [
        (ArgConstraint(pattern="INV-[0-9]{4}"), "INV-1234", True),
        (ArgConstraint(pattern="INV-[0-9]{4}"), "INV-1234; DROP TABLE", False),
        (ArgConstraint(pattern="INV-[0-9]{4}"), 1234, False),
        (ArgConstraint(one_of=["USD", "EUR"]), "EUR", True),
        (ArgConstraint(one_of=["USD", "EUR"]), "BTC", False),
        (ArgConstraint(min=1, max=500), 500, True),
        (ArgConstraint(min=1, max=500), 500.01, False),
        (ArgConstraint(min=1, max=500), 0, False),
        (ArgConstraint(max=500), "100", False),
        (ArgConstraint(max=500), True, False),
        (ArgConstraint(max_length=3), "abcd", False),
        (ArgConstraint(max_length=3), "abc", True),
    ],
)
def test_constraints(constraint: ArgConstraint, value: object, ok: bool) -> None:
    assert (constraint.violation("x", value) is None) is ok


def test_pattern_is_a_full_match_not_a_search() -> None:
    constraint = ArgConstraint(pattern="[a-z]+@example\\.com")
    assert constraint.violation("to", "a@example.com") is None
    assert constraint.violation("to", "a@example.com.evil.test") is not None


def test_required_and_strict_args() -> None:
    rule = AgentToolPolicy(constraints={"id": ArgConstraint(required=True)}, strict_args=True)
    assert rule.violation({}) == "required argument 'id' is missing"
    assert rule.violation({"id": 1}) is None
    assert "not permitted" in str(rule.violation({"id": 1, "admin": True}))


def test_invalid_regex_is_rejected_at_load_time() -> None:
    with pytest.raises(ValidationError):
        ArgConstraint(pattern="([unclosed")


def test_agent_cannot_reference_undefined_tool() -> None:
    with pytest.raises(ValidationError, match="undefined tools"):
        Policy.model_validate({"tools": {}, "agents": {"a": {"tools": {"ghost": {}}}}})


def test_unknown_keys_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate({"tools": {"t": {"risk": "low", "typo_field": True}}})
