#!/usr/bin/env python3
"""Compatibility surface for the packaged safety monitor.

New code should import :mod:`anthropic_safety_monitor`. This module preserves
historical imports without retaining decorative confidence scores or sentinel
answers.
"""

from __future__ import annotations

from anthropic_safety_monitor import (
    BatchReview,
    Decision,
    PolicyInputError,
    ReviewResult,
    Severity,
    ToolCall,
    review_batch,
    review_tool_call,
)


def evaluate(call: ToolCall) -> dict[str, object]:
    """Return the historical dictionary shape backed by the typed engine."""

    return review_tool_call(call).to_dict()


def batch(calls: list[ToolCall]) -> list[dict[str, object]]:
    """Review calls in order and return JSON-ready individual results."""

    return [result.to_dict() for result in review_batch(calls).results]


__all__ = [
    "BatchReview",
    "Decision",
    "PolicyInputError",
    "ReviewResult",
    "Severity",
    "ToolCall",
    "batch",
    "evaluate",
    "review_batch",
    "review_tool_call",
]


if __name__ == "__main__":
    from anthropic_safety_monitor.__main__ import main

    raise SystemExit(main())
