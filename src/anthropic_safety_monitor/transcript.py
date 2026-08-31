"""Hash-bound tool-review transcript receipts.

This module binds a proposed tool call to the deterministic policy result that
reviewed it. It does not execute tools or confer authorization.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass

from .policy import ReviewResult, ToolCall

TRANSCRIPT_SCHEMA = "glaciereq.anthropic-safety-monitor.tool-transcript.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class ToolTranscriptReceipt:
    sequence: int
    call: dict[str, object]
    review: dict[str, object]
    previous_receipt_sha256: str | None
    receipt_sha256: str

    def body(self) -> dict[str, object]:
        return {
            "schema": TRANSCRIPT_SCHEMA,
            "sequence": self.sequence,
            "call": self.call,
            "review": self.review,
            "previous_receipt_sha256": self.previous_receipt_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        payload = self.body()
        payload["receipt_sha256"] = self.receipt_sha256
        return payload


def bind_review(
    call: ToolCall,
    result: ReviewResult,
    *,
    sequence: int,
    previous_receipt_sha256: str | None = None,
) -> ToolTranscriptReceipt:
    """Bind one proposed call and its deterministic review into an immutable receipt."""

    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise ValueError("sequence must be a non-negative integer")
    call.validate()
    if result.call != call:
        raise ValueError("review result must belong to the supplied tool call")
    if previous_receipt_sha256 is not None and not _SHA256_RE.fullmatch(
        previous_receipt_sha256
    ):
        raise ValueError("previous_receipt_sha256 must be a lowercase SHA-256 digest")

    call_payload = {
        "name": call.name,
        "args": call.args,
        "metadata": dict(sorted(call.metadata.items())),
    }
    review_payload = {
        "decision": result.decision.value,
        "rule_id": result.rule_id,
        "reason": result.reason,
        "severity": result.severity.value,
        "requires_human_confirmation": result.requires_human_confirmation,
    }
    body = {
        "schema": TRANSCRIPT_SCHEMA,
        "sequence": sequence,
        "call": call_payload,
        "review": review_payload,
        "previous_receipt_sha256": previous_receipt_sha256,
    }
    return ToolTranscriptReceipt(
        sequence=sequence,
        call=call_payload,
        review=review_payload,
        previous_receipt_sha256=previous_receipt_sha256,
        receipt_sha256=_sha256(body),
    )


def verify_receipt(receipt: ToolTranscriptReceipt) -> bool:
    """Return whether the stored digest matches the canonical receipt body."""

    return bool(_SHA256_RE.fullmatch(receipt.receipt_sha256)) and _sha256(
        receipt.body()
    ) == receipt.receipt_sha256


def verify_chain(receipts: Iterable[ToolTranscriptReceipt]) -> bool:
    """Verify sequence continuity, body integrity, and predecessor binding."""

    rows = tuple(receipts)
    for index, receipt in enumerate(rows):
        if not verify_receipt(receipt):
            return False
        if index == 0:
            if receipt.sequence != 0 or receipt.previous_receipt_sha256 is not None:
                return False
            continue
        previous = rows[index - 1]
        if receipt.sequence != previous.sequence + 1:
            return False
        if receipt.previous_receipt_sha256 != previous.receipt_sha256:
            return False
    return True
