from __future__ import annotations

from dataclasses import replace

import pytest

from anthropic_safety_monitor import ToolCall, review_tool_call
from anthropic_safety_monitor.transcript import bind_review, verify_chain, verify_receipt


def test_tool_review_receipt_is_deterministic_and_bound_to_policy_result() -> None:
    call = ToolCall("git", "push --force origin main", metadata={"task": "deploy"})
    result = review_tool_call(call)
    first = bind_review(call, result, sequence=0)
    second = bind_review(call, result, sequence=0)
    assert first == second
    assert verify_receipt(first)
    assert first.review["decision"] == "confirm"
    assert first.review["rule_id"] == "ASM-CONFIRM-002"


def test_receipt_tampering_is_detected() -> None:
    call = ToolCall("git", "status --short")
    receipt = bind_review(call, review_tool_call(call), sequence=0)
    tampered = replace(receipt, review={**receipt.review, "decision": "deny"})
    assert verify_receipt(receipt)
    assert verify_receipt(tampered) is False


def test_receipt_chain_binds_each_review_to_predecessor() -> None:
    first_call = ToolCall("git", "status")
    first = bind_review(first_call, review_tool_call(first_call), sequence=0)
    second_call = ToolCall("bash", "rm -r ./build")
    second = bind_review(
        second_call,
        review_tool_call(second_call),
        sequence=1,
        previous_receipt_sha256=first.receipt_sha256,
    )
    assert verify_chain([first, second])
    broken = replace(second, previous_receipt_sha256="0" * 64)
    assert verify_chain([first, broken]) is False


def test_invalid_sequence_and_digest_fail_closed() -> None:
    call = ToolCall("git", "status")
    result = review_tool_call(call)
    with pytest.raises(ValueError, match="sequence"):
        bind_review(call, result, sequence=-1)
    with pytest.raises(ValueError, match="SHA-256"):
        bind_review(call, result, sequence=1, previous_receipt_sha256="not-a-digest")


def test_review_from_different_call_cannot_be_rebound() -> None:
    result = review_tool_call(ToolCall("git", "status"))
    with pytest.raises(ValueError, match="belong"):
        bind_review(ToolCall("git", "diff"), result, sequence=0)
