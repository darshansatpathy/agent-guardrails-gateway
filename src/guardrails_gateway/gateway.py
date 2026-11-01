"""The policy enforcement point.

Every tool call passes through `Gateway.evaluate` in a fixed order. The first check
that fails decides the outcome, and every decision is written to the audit log:

    1. grant      - signed, unexpired, unrevoked, issued to this agent for this task,
                    and naming this tool
    2. policy     - the tool is defined, and this agent is allowed to use it
    3. arguments  - every argument satisfies the agent's constraints for the tool
    4. rate limit - the agent has not exceeded its call budget for the tool
    5. human gate - high-risk, irreversible or approval-required tools, and egress
                    tools in a tainted session, need a matching human approval

Only then does `invoke` execute the tool, and only through the registry.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from typing import Any

from guardrails_gateway.approvals import ApprovalStore
from guardrails_gateway.audit import AuditLog
from guardrails_gateway.grants import GrantError, GrantIssuer
from guardrails_gateway.models import Decision, Outcome, ToolCall
from guardrails_gateway.observability import Timer, log_decision, set_span_attributes, span
from guardrails_gateway.policy import Policy
from guardrails_gateway.ratelimit import RateLimiter
from guardrails_gateway.taint import TaintTracker
from guardrails_gateway.tools import ToolRegistry

SENSITIVE_KEYS = ("password", "secret", "token", "api_key", "apikey", "card", "ssn", "iban")
MAX_RESULT_PREVIEW = 500


def redact(arguments: dict[str, Any]) -> dict[str, Any]:
    """Mask argument values whose names look sensitive before they reach the audit log."""
    return {
        key: "***" if any(s in key.lower() for s in SENSITIVE_KEYS) else value
        for key, value in arguments.items()
    }


@dataclass(frozen=True)
class InvokeResult:
    decision: Decision
    result: Any = None
    error: str | None = None


class Gateway:
    def __init__(
        self,
        policy: Policy,
        grants: GrantIssuer,
        audit: AuditLog,
        approvals: ApprovalStore,
        registry: ToolRegistry | None = None,
        rate_limiter: RateLimiter | None = None,
        taint: TaintTracker | None = None,
    ) -> None:
        self.policy = policy
        self.grants = grants
        self.audit = audit
        self.approvals = approvals
        self.registry = registry
        self.rate_limiter = rate_limiter or RateLimiter()
        self.taint = taint or TaintTracker()
        self.metrics: Counter[str] = Counter()

    def close(self) -> None:
        self.approvals.close()

    # ------------------------------------------------------------------ grants

    def issue_grant(
        self, agent_id: str, task_id: str, tools: list[str], ttl_seconds: int, issued_by: str
    ) -> str:
        allowed = set(self.policy.tools_for(agent_id))
        outside = sorted(set(tools) - allowed)
        if outside:
            raise GrantError(f"policy does not allow '{agent_id}' to use: {', '.join(outside)}")
        token = self.grants.issue(agent_id, task_id, tools, ttl_seconds)
        grant = self.grants.verify(token)
        self.audit.append(
            "grant.issued",
            {
                "grant_id": grant.grant_id,
                "agent_id": agent_id,
                "task_id": task_id,
                "tools": sorted(grant.tools),
                "expires_at": grant.expires_at,
                "issued_by": issued_by,
            },
        )
        return token

    def revoke_task(self, task_id: str, revoked_by: str) -> None:
        self.grants.revoke_task(task_id)
        self.audit.append("grant.task_revoked", {"task_id": task_id, "revoked_by": revoked_by})

    # ---------------------------------------------------------------- decisions

    def evaluate(self, call: ToolCall, grant_token: str) -> Decision:
        timer = Timer()
        attrs = {
            "aggw.agent_id": call.agent_id,
            "aggw.task_id": call.task_id,
            "aggw.session_id": call.session_id,
            "aggw.tool": call.tool,
        }
        with span("aggw.evaluate", attrs) as current:
            decision = self._decide(call, grant_token)
            set_span_attributes(
                current,
                {
                    "aggw.outcome": decision.outcome.value,
                    "aggw.rule": decision.rule,
                    "aggw.approval_id": decision.approval_id,
                },
            )
        self.metrics[f"decision.{decision.outcome.value}"] += 1
        self.metrics[f"rule.{decision.rule}"] += 1
        record = {
            "agent_id": call.agent_id,
            "task_id": call.task_id,
            "session_id": call.session_id,
            "tool": call.tool,
            "arguments": redact(call.arguments),
            "fingerprint": call.fingerprint(),
            "outcome": decision.outcome.value,
            "rule": decision.rule,
            "reason": decision.reason,
            "approval_id": decision.approval_id,
        }
        self.audit.append("decision", record)
        log_decision({**record, "decision_ms": timer.ms})
        return decision

    def invoke(self, call: ToolCall, grant_token: str) -> InvokeResult:
        """Evaluate, and if allowed, execute the tool through the registry."""
        decision = self.evaluate(call, grant_token)
        if not decision.allowed:
            return InvokeResult(decision=decision)
        if self.registry is None or not self.registry.has(call.tool):
            return InvokeResult(decision=decision, error=f"tool '{call.tool}' is not registered")
        started = time.perf_counter()
        try:
            result = self.registry.call(call.tool, call.arguments)
        except Exception as exc:  # tool adapters can fail in arbitrary ways
            self._record_result(call, ok=False, preview=repr(exc), started=started)
            return InvokeResult(decision=decision, error=f"{type(exc).__name__}: {exc}")
        self._record_result(call, ok=True, preview=repr(result), started=started)
        return InvokeResult(decision=decision, result=result)

    def record_tool_output(self, call: ToolCall) -> None:
        """For callers that execute tools themselves (e.g. the MCP proxy)."""
        tool = self.policy.tool(call.tool)
        if tool and tool.untrusted_output:
            self.taint.mark(call.session_id, call.tool)
            self.audit.append(
                "session.tainted", {"session_id": call.session_id, "source_tool": call.tool}
            )

    def decide_approval(
        self, approval_id: str, approve: bool, decided_by: str, note: str = ""
    ) -> dict[str, Any]:
        approval = self.approvals.decide(approval_id, approve, decided_by, note)
        self.audit.append(
            "approval.decided",
            {
                "approval_id": approval_id,
                "status": approval.status.value,
                "decided_by": decided_by,
                "note": note,
                "fingerprint": approval.fingerprint,
            },
        )
        return approval.to_dict()

    # ----------------------------------------------------------------- internals

    def _decide(self, call: ToolCall, grant_token: str) -> Decision:
        # 1. grant
        try:
            grant = self.grants.verify(grant_token)
        except GrantError as exc:
            return Decision.deny("grant.invalid", str(exc))
        if grant.agent_id != call.agent_id:
            return Decision.deny("grant.wrong_agent", "grant was issued to a different agent")
        if grant.task_id != call.task_id:
            return Decision.deny("grant.wrong_task", "grant was issued for a different task")
        if not grant.covers(call.tool):
            return Decision.deny("grant.tool_out_of_scope", f"grant does not cover '{call.tool}'")

        # 2. policy
        tool = self.policy.tool(call.tool)
        if tool is None:
            return Decision.deny("policy.unknown_tool", f"'{call.tool}' is not a defined tool")
        agent_tool = self.policy.agent_tool(call.agent_id, call.tool)
        if agent_tool is None:
            return Decision.deny(
                "policy.not_permitted", f"'{call.agent_id}' may not use '{call.tool}'"
            )

        # 3. arguments
        problem = agent_tool.violation(call.arguments)
        if problem:
            return Decision.deny("policy.argument_violation", problem)

        # 4. rate limit
        if agent_tool.rate_limit and not self.rate_limiter.check_and_record(
            call.agent_id,
            call.tool,
            agent_tool.rate_limit.max_calls,
            agent_tool.rate_limit.per_seconds,
        ):
            limit = agent_tool.rate_limit
            return Decision.deny(
                "rate_limit.exceeded",
                f"more than {limit.max_calls} calls in {limit.per_seconds}s",
            )

        # 5. human gate
        reasons: list[str] = []
        if tool.needs_human:
            reasons.append(f"'{call.tool}' is {self._risk_label(call.tool)}")
        if tool.egress and self.taint.is_tainted(call.session_id):
            sources = ", ".join(self.taint.sources(call.session_id))
            reasons.append(
                f"session read untrusted content ({sources}) and this tool sends data out"
            )
        if reasons:
            approval = self.approvals.consume(call)
            if approval is not None:
                self.audit.append(
                    "approval.consumed",
                    {"approval_id": approval.approval_id, "fingerprint": approval.fingerprint},
                )
                return Decision.allow("approval.granted", f"approved by {approval.decided_by}")
            pending = self.approvals.request(
                call, "; ".join(reasons), self.policy.defaults.approval_ttl_seconds
            )
            self.audit.append(
                "approval.requested",
                {"approval_id": pending.approval_id, "fingerprint": pending.fingerprint},
            )
            return Decision(
                outcome=Outcome.REQUIRE_APPROVAL,
                rule="human_gate",
                reason="; ".join(reasons),
                approval_id=pending.approval_id,
            )

        return Decision.allow()

    def _record_result(self, call: ToolCall, ok: bool, preview: str, started: float) -> None:
        self.audit.append(
            "tool.result",
            {
                "agent_id": call.agent_id,
                "session_id": call.session_id,
                "tool": call.tool,
                "ok": ok,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "preview": preview[:MAX_RESULT_PREVIEW],
            },
        )
        self.metrics[f"tool.{'ok' if ok else 'error'}"] += 1
        if ok:
            self.record_tool_output(call)

    def _risk_label(self, tool_name: str) -> str:
        tool = self.policy.tools[tool_name]
        if tool.irreversible:
            return "irreversible"
        if tool.requires_approval:
            return "marked as requiring approval"
        return f"{tool.risk.value} risk"
