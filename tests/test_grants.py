from __future__ import annotations

import pytest

from guardrails_gateway.grants import GrantError, GrantIssuer
from tests.conftest import SECRET, FakeClock


@pytest.fixture
def issuer(clock: FakeClock) -> GrantIssuer:
    return GrantIssuer(SECRET, max_ttl_seconds=3600, clock=clock)


def test_round_trip(issuer: GrantIssuer) -> None:
    token = issuer.issue("agent", "task", ["b", "a", "a"], 60)
    grant = issuer.verify(token)
    assert grant.agent_id == "agent"
    assert grant.task_id == "task"
    assert grant.tools == frozenset({"a", "b"})
    assert grant.covers("a") and not grant.covers("c")


def test_forged_signature_is_rejected(issuer: GrantIssuer) -> None:
    body, _ = issuer.issue("agent", "task", ["a"], 60).split(".")
    with pytest.raises(GrantError, match="signature"):
        issuer.verify(body + ".AAAA")


def test_payload_tampering_is_rejected(issuer: GrantIssuer) -> None:
    token = issuer.issue("agent", "task", ["a"], 60)
    other = issuer.issue("agent", "task", ["a", "delete_everything"], 60)
    forged = other.split(".")[0] + "." + token.split(".")[1]
    with pytest.raises(GrantError, match="signature"):
        issuer.verify(forged)


def test_key_from_another_deployment_is_rejected(issuer: GrantIssuer, clock: FakeClock) -> None:
    other = GrantIssuer(b"x" * 32, clock=clock)
    with pytest.raises(GrantError):
        issuer.verify(other.issue("agent", "task", ["a"], 60))


def test_expiry(issuer: GrantIssuer, clock: FakeClock) -> None:
    token = issuer.issue("agent", "task", ["a"], 60)
    clock.advance(59)
    issuer.verify(token)
    clock.advance(1)
    with pytest.raises(GrantError, match="expired"):
        issuer.verify(token)


def test_ttl_ceiling(issuer: GrantIssuer) -> None:
    with pytest.raises(GrantError, match="maximum"):
        issuer.issue("agent", "task", ["a"], 3601)


def test_revoke_single_grant_and_whole_task(issuer: GrantIssuer) -> None:
    first = issuer.issue("agent", "task-1", ["a"], 60)
    second = issuer.issue("agent", "task-1", ["a"], 60)
    issuer.revoke(issuer.verify(first).grant_id)
    with pytest.raises(GrantError, match="revoked"):
        issuer.verify(first)
    issuer.verify(second)
    issuer.revoke_task("task-1")
    with pytest.raises(GrantError, match="revoked"):
        issuer.verify(second)


@pytest.mark.parametrize("token", ["", "no-dot", "a.b.c", "!!!.???"])
def test_malformed_tokens(issuer: GrantIssuer, token: str) -> None:
    with pytest.raises(GrantError):
        issuer.verify(token)


def test_short_secret_is_refused() -> None:
    with pytest.raises(ValueError):
        GrantIssuer(b"too-short")


def test_empty_tool_list_is_refused(issuer: GrantIssuer) -> None:
    with pytest.raises(GrantError):
        issuer.issue("agent", "task", [], 60)
