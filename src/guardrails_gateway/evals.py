"""Attack-scenario evaluation.

Runs every scenario in `evals/scenarios.yaml` against a fresh gateway with the demo
tools, on a controllable clock, and checks two things:

- **Attacks**: the harmful action never executes. Every step must produce exactly the
  expected outcome (denied, needs approval, rejected, detected).
- **Benign work**: legitimate actions are allowed. A guardrail that blocks everything
  is not a guardrail anyone keeps switched on, so false positives count as failures.

`aggw eval` prints a report and exits non-zero on any failure, so CI fails if a change
to code or policy lets an attack through or starts blocking legitimate work.
"""

from __future__ import annotations

import json
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from guardrails_gateway.approvals import ApprovalError, ApprovalStatus, ApprovalStore
from guardrails_gateway.audit import AuditLog
from guardrails_gateway.gateway import Gateway
from guardrails_gateway.grants import GrantIssuer
from guardrails_gateway.models import Outcome, ToolCall
from guardrails_gateway.policy import Policy
from guardrails_gateway.ratelimit import RateLimiter
from guardrails_gateway.tools import demo_registry

SECRET = b"eval-secret-eval-secret-eval-secret!!"
FORGER = b"attacker-key-attacker-key-attacker!!"
SUPPORT_TASK_TOOLS = ["search_docs", "read_invoice", "web_fetch", "send_email", "refund_payment"]
OUTCOME_NAMES = {
    Outcome.ALLOW: "allowed",
    Outcome.DENY: "denied",
    Outcome.REQUIRE_APPROVAL: "needs_approval",
}
_PACKAGED = Path(__file__).resolve().parent / "evals" / "scenarios.yaml"
_REPO = Path(__file__).resolve().parents[2] / "evals" / "scenarios.yaml"
DEFAULT_SCENARIOS = _PACKAGED if _PACKAGED.exists() else _REPO


class _Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class ScenarioResult:
    scenario_id: str
    kind: str
    category: str
    title: str
    passed: bool
    detail: str = ""
    observed: list[str] = field(default_factory=list)


@dataclass
class EvalReport:
    results: list[ScenarioResult]

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    def by_category(self) -> list[tuple[str, str, int, int]]:
        groups: dict[tuple[str, str], list[ScenarioResult]] = defaultdict(list)
        for r in self.results:
            groups[(r.kind, r.category)].append(r)
        rows = [
            (kind, cat, sum(r.passed for r in rs), len(rs)) for (kind, cat), rs in groups.items()
        ]
        return sorted(rows, key=lambda row: (row[0] != "attack", row[1]))

    def markdown(self) -> str:
        attacks = [r for r in self.results if r.kind == "attack"]
        benign = [r for r in self.results if r.kind == "benign"]
        lines = [
            f"**Attacks contained: {sum(r.passed for r in attacks)}/{len(attacks)}** · "
            f"**Legitimate actions allowed: {sum(r.passed for r in benign)}/{len(benign)}**",
            "",
            "| Category | Kind | Passed |",
            "|---|---|---|",
        ]
        for kind, cat, ok, total in self.by_category():
            lines.append(f"| {cat} | {kind} | {ok}/{total} |")
        failures = [r for r in self.results if not r.passed]
        if failures:
            lines += ["", "Failures:", ""]
            lines += [f"- {r.scenario_id} {r.title}: {r.detail}" for r in failures]
        return "\n".join(lines)


def load_scenarios(path: str | Path = DEFAULT_SCENARIOS) -> list[dict[str, Any]]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    scenarios = data.get("scenarios", [])
    if not isinstance(scenarios, list):
        raise ValueError("'scenarios' must be a list")
    return scenarios


def run_suite(
    policy_path: str | Path, scenarios_path: str | Path = DEFAULT_SCENARIOS
) -> EvalReport:
    policy = Policy.from_yaml(policy_path)
    return EvalReport([run_scenario(policy, s) for s in load_scenarios(scenarios_path)])


def run_scenario(policy: Policy, scenario: dict[str, Any]) -> ScenarioResult:
    result = ScenarioResult(
        scenario_id=str(scenario["id"]),
        kind=str(scenario.get("kind", "attack")),
        category=str(scenario.get("category", "Uncategorised")),
        title=str(scenario.get("title", "")),
        passed=True,
    )
    with tempfile.TemporaryDirectory() as tmp:
        clock = _Clock()
        gateway = Gateway(
            policy=policy,
            grants=GrantIssuer(SECRET, max_ttl_seconds=86_400, clock=clock),
            audit=AuditLog(Path(tmp) / "audit.jsonl", key=b"eval-audit-key"),
            approvals=ApprovalStore(clock=clock),
            registry=demo_registry(),
            rate_limiter=RateLimiter(clock=clock),
        )
        try:
            runner = _Runner(gateway, clock)
            for index, step in enumerate(scenario.get("steps", []), start=1):
                repeat = int(step.get("repeat", 1))
                for _ in range(repeat):
                    observed = runner.step(step)
                    result.observed.append(observed)
                    expected = str(step.get("expect", ""))
                    if expected and observed != expected:
                        result.passed = False
                        result.detail = f"step {index}: expected {expected}, got {observed}"
                        return result
        finally:
            gateway.close()
    return result


class _Runner:
    def __init__(self, gateway: Gateway, clock: _Clock) -> None:
        self.gw = gateway
        self.clock = clock
        self.task = "EVAL-1"
        self.last_approval: str | None = None
        # Issued when the scenario starts, so clock steps can expire it.
        self._grants: dict[str, str] = {
            "support-agent": gateway.grants.issue(
                "support-agent", self.task, SUPPORT_TASK_TOOLS, 3600
            )
        }

    def step(self, step: dict[str, Any]) -> str:
        if "call" in step:
            return self._call(step["call"])
        if "approve" in step:
            return self._approve(step["approve"])
        if "revoke_task" in step:
            self.gw.revoke_task(self.task, revoked_by=str(step["revoke_task"].get("by", "eval")))
            return "ok"
        if "advance_clock" in step:
            self.clock.now += float(step["advance_clock"])
            return "ok"
        if "tamper_audit" in step:
            return self._tamper()
        raise ValueError(f"unknown step: {sorted(step)}")

    def _grant_for(self, agent: str, tool: str, kind: str) -> str:
        if kind == "forged":
            return GrantIssuer(FORGER, clock=self.clock).issue(agent, self.task, [tool], 3600)
        if kind == "other_task":
            return self.gw.grants.issue(agent, "SOME-OTHER-TASK", [tool], 3600)
        if agent in self._grants:
            return self._grants[agent]
        # Other agents get an over-broad grant that names the tool, so the eval proves
        # the policy layer denies it even when the orchestrator granted too much.
        return self.gw.grants.issue(agent, self.task, [tool], 3600)

    def _call(self, spec: dict[str, Any]) -> str:
        agent = str(spec.get("agent", "support-agent"))
        tool = str(spec["tool"])
        call = ToolCall(
            agent_id=agent,
            task_id=self.task,
            session_id=str(spec.get("session", "s1")),
            tool=tool,
            arguments=dict(spec.get("args") or {}),
        )
        outcome = self.gw.invoke(
            call, self._grant_for(agent, tool, str(spec.get("grant", "default")))
        )
        if outcome.decision.approval_id:
            self.last_approval = outcome.decision.approval_id
        if outcome.decision.allowed and outcome.error:
            return "error"
        return OUTCOME_NAMES[outcome.decision.outcome]

    def _approve(self, spec: dict[str, Any]) -> str:
        pending = self.gw.approvals.list(ApprovalStatus.PENDING)
        approval_id = self.last_approval or (pending[-1].approval_id if pending else None)
        if approval_id is None:
            return "no_pending_approval"
        try:
            self.gw.decide_approval(approval_id, True, decided_by=str(spec.get("by", "reviewer")))
        except ApprovalError:
            return "rejected"
        return "ok"

    def _tamper(self) -> str:
        path = self.gw.audit.path
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            record = json.loads(line)
            if record["event"] == "decision":
                record["data"]["arguments"] = {"edited": True}
                lines[i] = json.dumps(record, sort_keys=True)
                break
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return "detected" if not self.gw.audit.verify().ok else "undetected"
