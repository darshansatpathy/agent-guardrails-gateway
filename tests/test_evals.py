from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from guardrails_gateway.evals import load_scenarios, run_scenario, run_suite
from guardrails_gateway.policy import Policy
from tests.conftest import POLICY_PATH, ROOT

SCENARIOS = ROOT / "evals" / "scenarios.yaml"


def _weakened(tmp_path: Path, mutate: object) -> Path:
    data = yaml.safe_load(POLICY_PATH.read_text())
    mutate(data)  # type: ignore[operator]
    path = tmp_path / "weak.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


def test_shipped_policy_contains_every_attack_and_allows_benign_work() -> None:
    report = run_suite(POLICY_PATH, SCENARIOS)
    failures = [(r.scenario_id, r.detail) for r in report.results if not r.passed]
    assert failures == []
    assert sum(r.kind == "attack" for r in report.results) >= 20
    assert sum(r.kind == "benign" for r in report.results) >= 5
    assert "Attacks contained" in report.markdown()


def test_raising_the_refund_limit_is_caught(tmp_path: Path) -> None:
    def mutate(d: dict) -> None:  # type: ignore[type-arg]
        d["agents"]["support-agent"]["tools"]["refund_payment"]["constraints"]["amount"]["max"] = (
            100000
        )

    report = run_suite(_weakened(tmp_path, mutate), SCENARIOS)
    failed = {r.scenario_id for r in report.results if not r.passed}
    assert "ATK-08" in failed
    assert not report.passed


def test_loosening_the_recipient_pattern_is_caught(tmp_path: Path) -> None:
    def mutate(d: dict) -> None:  # type: ignore[type-arg]
        d["agents"]["support-agent"]["tools"]["send_email"]["constraints"]["to"]["pattern"] = ".*"

    failed = {
        r.scenario_id
        for r in run_suite(_weakened(tmp_path, mutate), SCENARIOS).results
        if not r.passed
    }
    assert {"ATK-01", "ATK-03"} <= failed


def test_removing_taint_marking_is_caught(tmp_path: Path) -> None:
    def mutate(d: dict) -> None:  # type: ignore[type-arg]
        d["tools"]["web_fetch"]["untrusted_output"] = False

    failed = {
        r.scenario_id
        for r in run_suite(_weakened(tmp_path, mutate), SCENARIOS).results
        if not r.passed
    }
    assert "ATK-02" in failed


def test_over_blocking_is_caught_as_a_false_positive(tmp_path: Path) -> None:
    def mutate(d: dict) -> None:  # type: ignore[type-arg]
        d["tools"]["search_docs"]["requires_approval"] = True

    failed = {
        r.scenario_id
        for r in run_suite(_weakened(tmp_path, mutate), SCENARIOS).results
        if not r.passed
    }
    assert "BEN-01" in failed


def test_unknown_step_type_is_an_error() -> None:
    policy = Policy.from_yaml(POLICY_PATH)
    with pytest.raises(ValueError, match="unknown step"):
        run_scenario(policy, {"id": "X", "steps": [{"teleport": {}}]})


def test_scenarios_file_is_well_formed() -> None:
    scenarios = load_scenarios(SCENARIOS)
    ids = [s["id"] for s in scenarios]
    assert len(ids) == len(set(ids))
    assert all(s.get("kind") in {"attack", "benign"} for s in scenarios)
