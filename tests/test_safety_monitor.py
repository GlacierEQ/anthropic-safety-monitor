from __future__ import annotations

import json

import pytest

from anthropic_safety_monitor import (
    MAX_ARGUMENT_BYTES,
    Decision,
    PolicyInputError,
    Severity,
    ToolCall,
    review_batch,
    review_tool_call,
)
from safety_monitor import evaluate


@pytest.mark.parametrize(
    ("tool", "args", "rule_id"),
    [
        ("bash", "rm -rf /", "ASM-DENY-004"),
        ("bash", "rm -fr -- /etc", "ASM-DENY-004"),
        ("bash", "-lc 'rm -rf /home'", "ASM-DENY-004"),
        ("mkfs.ext4", "/dev/sda1", "ASM-DENY-002"),
        ("bash", "dd if=/dev/zero of=/dev/sda", "ASM-DENY-003"),
        ("bash", ":(){ :|:& };:", "ASM-DENY-001"),
    ],
)
def test_critical_patterns_are_denied(tool: str, args: str, rule_id: str) -> None:
    result = review_tool_call(ToolCall(tool, args))
    assert result.decision is Decision.DENY
    assert result.rule_id == rule_id
    assert result.severity is Severity.CRITICAL
    assert result.requires_human_confirmation is False


@pytest.mark.parametrize(
    ("tool", "args", "rule_id"),
    [
        ("bash", "rm -r ./build", "ASM-CONFIRM-001"),
        ("git", "push --force origin feature", "ASM-CONFIRM-002"),
        ("bash", "git push --force-with-lease origin main", "ASM-CONFIRM-002"),
        ("kubectl", "delete deployment api", "ASM-CONFIRM-003"),
        ("terraform", "destroy -auto-approve", "ASM-CONFIRM-004"),
        ("reboot", "", "ASM-CONFIRM-005"),
        ("database", "DROP   TABLE accounts", "ASM-CONFIRM-006"),
    ],
)
def test_recoverable_destructive_actions_require_confirmation(
    tool: str,
    args: str,
    rule_id: str,
) -> None:
    result = review_tool_call(ToolCall(tool, args))
    assert result.decision is Decision.CONFIRM
    assert result.rule_id == rule_id
    assert result.severity is Severity.HIGH
    assert result.requires_human_confirmation is True


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("bash", "ls -la"),
        ("git", "status --short"),
        ("kubectl", "get pods"),
        ("python", "-m compileall src"),
    ],
)
def test_nonmatching_calls_are_allowed(tool: str, args: str) -> None:
    result = review_tool_call(ToolCall(tool, args))
    assert result.decision is Decision.ALLOW
    assert result.rule_id == "ASM-ALLOW-DEFAULT"
    assert result.severity is Severity.NONE


def test_result_is_stable_json_without_decorative_fields() -> None:
    payload = review_tool_call(
        ToolCall("git", "status", metadata={"trace": "abc", "case": "demo"})
    ).to_dict()
    assert payload["schema"] == "glaciereq.anthropic-safety-monitor.review.v1"
    assert payload["call"]["metadata"] == {"case": "demo", "trace": "abc"}
    assert "answer" not in payload
    assert "confidence" not in payload
    json.dumps(payload, sort_keys=True)


def test_compatibility_evaluate_routes_through_typed_engine() -> None:
    payload = evaluate(ToolCall("bash", "git push --force origin main"))
    assert payload["decision"] == "confirm"
    assert payload["rule_id"] == "ASM-CONFIRM-002"
    assert "answer" not in payload


def test_batch_preserves_order_and_reports_strongest_decision() -> None:
    review = review_batch(
        [
            ToolCall("git", "status"),
            ToolCall("git", "push --force origin main"),
            ToolCall("bash", "rm -rf /"),
        ]
    )
    assert [result.decision for result in review.results] == [
        Decision.ALLOW,
        Decision.CONFIRM,
        Decision.DENY,
    ]
    assert review.overall_decision is Decision.DENY
    assert review.to_dict()["counts"] == {
        "allow": 1,
        "confirm": 1,
        "deny": 1,
        "total": 3,
    }


def test_empty_batch_is_allowed_with_zero_counts() -> None:
    review = review_batch([])
    assert review.overall_decision is Decision.ALLOW
    assert review.to_dict()["counts"]["total"] == 0


@pytest.mark.parametrize(
    "call",
    [
        ToolCall(""),
        ToolCall("bash", "unterminated '"),
        ToolCall("bash", "-lc"),
        ToolCall("bash", "x" * (MAX_ARGUMENT_BYTES + 1)),
    ],
)
def test_malformed_calls_fail_closed(call: ToolCall) -> None:
    with pytest.raises(PolicyInputError):
        review_tool_call(call)


def test_non_string_metadata_is_rejected() -> None:
    call = ToolCall("git", "status", metadata={"attempt": 1})  # type: ignore[dict-item]
    with pytest.raises(PolicyInputError, match="metadata keys and values"):
        review_tool_call(call)
