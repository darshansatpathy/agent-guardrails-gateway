from __future__ import annotations

from collections.abc import Iterator

import pytest

from guardrails_gateway.approvals import ApprovalError, ApprovalStatus, ApprovalStore
from tests.conftest import FakeClock, make_call


@pytest.fixture
def store(clock: FakeClock) -> Iterator[ApprovalStore]:
    s = ApprovalStore(clock=clock)
    yield s
    s.close()


def test_pending_request_is_deduplicated(store: ApprovalStore) -> None:
    call = make_call("refund_payment", invoice_id="INV-1001", amount=10, currency="USD")
    first = store.request(call, "high risk", 60)
    second = store.request(call, "high risk", 60)
    assert first.approval_id == second.approval_id
    assert len(store.list(ApprovalStatus.PENDING)) == 1


def test_agent_cannot_approve_itself(store: ApprovalStore) -> None:
    approval = store.request(make_call("refund_payment", amount=10), "r", 60)
    with pytest.raises(ApprovalError, match="own request"):
        store.decide(approval.approval_id, True, decided_by="support-agent")


def test_approval_is_single_use(store: ApprovalStore) -> None:
    call = make_call("refund_payment", amount=10)
    approval = store.request(call, "r", 60)
    store.decide(approval.approval_id, True, decided_by="reviewer")
    assert store.consume(call) is not None
    assert store.consume(call) is None
    assert store.get(approval.approval_id).status is ApprovalStatus.CONSUMED


def test_approval_is_bound_to_exact_arguments(store: ApprovalStore) -> None:
    approved = make_call("refund_payment", amount=10)
    larger = make_call("refund_payment", amount=10_000)
    approval = store.request(approved, "r", 60)
    store.decide(approval.approval_id, True, decided_by="reviewer")
    assert store.consume(larger) is None
    assert store.consume(approved) is not None


def test_denied_approval_cannot_be_consumed(store: ApprovalStore) -> None:
    call = make_call("refund_payment", amount=10)
    approval = store.request(call, "r", 60)
    store.decide(approval.approval_id, False, decided_by="reviewer", note="no")
    assert store.consume(call) is None
    with pytest.raises(ApprovalError, match="denied"):
        store.decide(approval.approval_id, True, decided_by="reviewer")


def test_pending_request_expires(store: ApprovalStore, clock: FakeClock) -> None:
    approval = store.request(make_call("refund_payment", amount=10), "r", 60)
    clock.advance(61)
    with pytest.raises(ApprovalError):
        store.decide(approval.approval_id, True, decided_by="reviewer")
    assert store.get(approval.approval_id).status is ApprovalStatus.EXPIRED


def test_unused_approval_expires(store: ApprovalStore, clock: FakeClock) -> None:
    call = make_call("refund_payment", amount=10)
    approval = store.request(call, "r", 60)
    store.decide(approval.approval_id, True, decided_by="reviewer")
    clock.advance(61)
    assert store.consume(call) is None


def test_unknown_approval(store: ApprovalStore) -> None:
    with pytest.raises(ApprovalError, match="unknown"):
        store.get("apr_missing")
