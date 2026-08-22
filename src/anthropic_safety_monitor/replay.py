"""Semantic replay ledger for deterministic safety-policy regression detection."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping, Any

from .policy import ToolCall, review_tool_call

REPLAY_SCHEMA = "glaciereq.anthropic-safety-monitor.replay.v1"


@dataclass(frozen=True, slots=True)
class ReplayScenario:
    scenario_id: str
    call: ToolCall
    expected_decision: str
    expected_rule_id: str
    expected_severity: str

    def __post_init__(self) -> None:
        if not self.scenario_id.strip():
            raise ValueError("scenario_id must be non-empty")
        for name in ("expected_decision", "expected_rule_id", "expected_severity"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must be non-empty")

    def baseline_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "call": {
                "name": self.call.name,
                "args": self.call.args,
                "metadata": dict(sorted(self.call.metadata.items())),
            },
            "expected": {
                "decision": self.expected_decision,
                "rule_id": self.expected_rule_id,
                "severity": self.expected_severity,
            },
        }


@dataclass(frozen=True, slots=True)
class ReplayEntry:
    scenario_id: str
    matched: bool
    expected: Mapping[str, str]
    actual: Mapping[str, str]
    result_fingerprint: str

    def as_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "matched": self.matched,
            "expected": dict(self.expected),
            "actual": dict(self.actual),
            "result_fingerprint": self.result_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class ReplayReport:
    entries: tuple[ReplayEntry, ...]
    baseline_fingerprint: str

    @property
    def drift_count(self) -> int:
        return sum(not entry.matched for entry in self.entries)

    @property
    def passed(self) -> bool:
        return self.drift_count == 0

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": REPLAY_SCHEMA,
            "passed": self.passed,
            "scenario_count": len(self.entries),
            "drift_count": self.drift_count,
            "baseline_fingerprint": self.baseline_fingerprint,
            "entries": [entry.as_dict() for entry in self.entries],
        }

    @property
    def fingerprint(self) -> str:
        encoded = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()


def _fingerprint(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()


def replay_scenarios(scenarios: Iterable[ReplayScenario]) -> ReplayReport:
    rows = tuple(scenarios)
    ids = [scenario.scenario_id for scenario in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("scenario_id values must be unique")

    baseline = [scenario.baseline_dict() for scenario in rows]
    entries: list[ReplayEntry] = []
    for scenario in rows:
        result = review_tool_call(scenario.call)
        actual = {
            "decision": result.decision.value,
            "rule_id": result.rule_id,
            "severity": result.severity.value,
        }
        expected = {
            "decision": scenario.expected_decision,
            "rule_id": scenario.expected_rule_id,
            "severity": scenario.expected_severity,
        }
        entries.append(
            ReplayEntry(
                scenario_id=scenario.scenario_id,
                matched=actual == expected,
                expected=expected,
                actual=actual,
                result_fingerprint=_fingerprint(result.to_dict()),
            )
        )
    return ReplayReport(tuple(entries), _fingerprint(baseline))


def scenarios_from_data(data: Iterable[Mapping[str, Any]]) -> tuple[ReplayScenario, ...]:
    scenarios: list[ReplayScenario] = []
    for row in data:
        call_data = row["call"]
        expected = row["expected"]
        scenarios.append(
            ReplayScenario(
                scenario_id=str(row["scenario_id"]),
                call=ToolCall(
                    name=str(call_data["name"]),
                    args=str(call_data.get("args", "")),
                    metadata={str(k): str(v) for k, v in call_data.get("metadata", {}).items()},
                ),
                expected_decision=str(expected["decision"]),
                expected_rule_id=str(expected["rule_id"]),
                expected_severity=str(expected["severity"]),
            )
        )
    return tuple(scenarios)


def load_scenarios(path: str | Path) -> tuple[ReplayScenario, ...]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schema") != "glaciereq.anthropic-safety-monitor.replay-corpus.v1":
        raise ValueError("unsupported replay corpus schema")
    return scenarios_from_data(payload["scenarios"])
