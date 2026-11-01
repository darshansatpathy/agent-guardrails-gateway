from __future__ import annotations

import io
from pathlib import Path

from guardrails_gateway import cli, demo
from guardrails_gateway.audit import AuditLog
from tests.conftest import POLICY_PATH


def test_demo_produces_expected_outcomes(tmp_path: Path) -> None:
    out = io.StringIO()
    result = demo.run(tmp_path, POLICY_PATH, out=out)
    result.gw.close()
    outcomes = [o for _, o in result.results]
    assert outcomes == [
        "allow",  # lookup
        "deny",  # outside grant
        "deny",  # over refund limit
        "require_approval",  # high-risk refund
        "deny",  # self-approval rejected
        "allow",  # approved refund runs
        "require_approval",  # replay needs new approval
        "allow",  # clean email
        "allow",  # web fetch (taints)
        "deny",  # exfiltration address
        "require_approval",  # tainted egress
        "deny",  # revoked task
        "deny",  # tampering detected
    ]
    assert "fail" not in outcomes
    assert "first_bad_seq" in out.getvalue()


def test_validate_policy_cli(capsys: object) -> None:
    assert cli.main(["validate-policy", str(POLICY_PATH)]) == 0


def test_validate_policy_rejects_bad_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("agents:\n  a:\n    tools:\n      ghost: {}\n")
    assert cli.main(["validate-policy", str(bad)]) == 1


def test_verify_audit_cli(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    log.append("x", {"n": 1})
    assert cli.main(["verify-audit", str(path)]) == 0
    path.write_text(path.read_text().replace('"n": 1', '"n": 2'))
    assert cli.main(["verify-audit", str(path)]) == 1


def test_eval_cli_writes_report(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    assert cli.main(["eval", "--policy", str(POLICY_PATH), "--markdown", str(out)]) == 0
    assert "Attacks contained" in out.read_text()
