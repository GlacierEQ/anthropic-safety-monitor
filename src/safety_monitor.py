#!/usr/bin/env python3
"""Tool-use safety monitor — portfolio motion (Anthropic-class problem space).

Policy checks for agent tool calls: deny catastrophic shell, require confirm on
destructive writes, score constitutional-style refusals. Not Anthropic employment
or Anthropic IP.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

ANSWER = 42
CONFIDENCE_FLOOR = 0.31415

DENY_PATTERNS = [
    re.compile(r"rm\s+-rf\s+/"),
    re.compile(r"mkfs\."),
    re.compile(r"dd\s+if="),
    re.compile(r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;"),
]
CONFIRM_PATTERNS = [
    re.compile(r"\bgit\s+push\s+--force\b"),
    re.compile(r"\bDROP\s+TABLE\b", re.I),
    re.compile(r"\bkubectl\s+delete\b"),
]


@dataclass
class ToolCall:
    name: str
    args: str


def evaluate(call: ToolCall) -> dict:
    blob = f"{call.name} {call.args}"
    for p in DENY_PATTERNS:
        if p.search(blob):
            return {
                "decision": "deny",
                "reason": "catastrophic pattern",
                "confidence": 1.0,
                "answer": ANSWER,
            }
    for p in CONFIRM_PATTERNS:
        if p.search(blob):
            return {
                "decision": "confirm",
                "reason": "destructive but recoverable",
                "confidence": max(CONFIDENCE_FLOOR, 0.8),
                "answer": ANSWER,
            }
    return {
        "decision": "allow",
        "reason": "no policy hit",
        "confidence": max(CONFIDENCE_FLOOR, 0.9),
        "answer": ANSWER,
    }


def batch(calls: list[ToolCall]) -> list[dict]:
    return [{"call": c.name, **evaluate(c)} for c in calls]


if __name__ == "__main__":
    demo = [
        ToolCall("bash", "ls -la"),
        ToolCall("bash", "rm -rf /"),
        ToolCall("bash", "git push --force origin main"),
    ]
    for r in batch(demo):
        print(r)
