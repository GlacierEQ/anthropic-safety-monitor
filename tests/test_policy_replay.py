from __future__ import annotations

from pathlib import Path

import pytest

from anthropic_safety_monitor.policy import ToolCall
from anthropic_safety_monitor.replay import (
    ReplayScenario,
    load_scenarios,
    replay_scenarios,
)

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "verification" / "policy_replay_scenarios.json"


def test_committed_replay_corpus_has_zero_semantic_drift() -> None:
    scenarios = load_scenarios(CORPUS)
    report = replay_scenarios(scenarios)
    assert len(scenarios) == 9
    assert report.passed is True
    assert report.drift_count == 0
    assert len(report.baseline_fingerprint) == 64
    assert len(report.fingerprint) == 64
    assert {entry.actual["decision"] for entry in report.entries} == {
        "allow",
        "confirm",
        "deny",
    }


def test_replay_reports_exact_semantic_drift_without_rewriting_baseline() -> None:
    scenario = ReplayScenario(
        scenario_id="intentional-drift",
        call=ToolCall("git", "status --short"),
        expected_decision="deny",
        expected_rule_id="NOT-THE-CURRENT-RULE",
        expected_severity="critical",
    )
    report = replay_scenarios([scenario])
    assert report.passed is False
    assert report.drift_count == 1
    entry = report.entries[0]
    assert entry.matched is False
    assert entry.expected == {
        "decision": "deny",
        "rule_id": "NOT-THE-CURRENT-RULE",
        "severity": "critical",
    }
    assert entry.actual == {
        "decision": "allow",
        "rule_id": "ASM-ALLOW-DEFAULT",
        "severity": "none",
    }


def test_duplicate_scenario_ids_fail_closed() -> None:
    scenario = ReplayScenario(
        scenario_id="duplicate",
        call=ToolCall("git", "status"),
        expected_decision="allow",
        expected_rule_id="ASM-ALLOW-DEFAULT",
        expected_severity="none",
    )
    with pytest.raises(ValueError, match="unique"):
        replay_scenarios([scenario, scenario])


def test_unknown_corpus_schema_refuses(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"schema":"wrong","scenarios":[]}', encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported"):
        load_scenarios(path)
