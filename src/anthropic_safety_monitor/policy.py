from __future__ import annotations

import re
import shlex
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath

SCHEMA = "glaciereq.anthropic-safety-monitor.review.v1"
BATCH_SCHEMA = "glaciereq.anthropic-safety-monitor.batch.v1"
MAX_ARGUMENT_BYTES = 65_536
SHELL_TOOLS = frozenset({"bash", "sh", "shell", "terminal", "zsh"})
CRITICAL_ROOTS = frozenset(
    {
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/opt",
        "/proc",
        "/root",
        "/sbin",
        "/sys",
        "/usr",
        "/var",
    }
)
DROP_TABLE_RE = re.compile(r"\bdrop\s+table\b", re.IGNORECASE)
FORK_BOMB_RE = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")


class PolicyInputError(ValueError):
    """Raised when a proposed tool call is malformed or cannot be reviewed safely."""


class Decision(StrEnum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    DENY = "deny"


class Severity(StrEnum):
    NONE = "none"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_DECISION_RANK = {
    Decision.ALLOW: 0,
    Decision.CONFIRM: 1,
    Decision.DENY: 2,
}


@dataclass(frozen=True, slots=True)
class ToolCall:
    name: str
    args: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise PolicyInputError("tool name must be non-empty text")
        if not isinstance(self.args, str):
            raise PolicyInputError("tool arguments must be text")
        if len(self.args.encode("utf-8")) > MAX_ARGUMENT_BYTES:
            raise PolicyInputError(
                f"tool arguments exceed the {MAX_ARGUMENT_BYTES}-byte review limit"
            )
        if not isinstance(self.metadata, Mapping):
            raise PolicyInputError("metadata must be a string mapping")
        for key, value in self.metadata.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise PolicyInputError("metadata keys and values must be text")


@dataclass(frozen=True, slots=True)
class ReviewResult:
    call: ToolCall
    decision: Decision
    rule_id: str
    reason: str
    severity: Severity
    requires_human_confirmation: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": SCHEMA,
            "call": {
                "name": self.call.name,
                "args": self.call.args,
                "metadata": dict(sorted(self.call.metadata.items())),
            },
            "decision": self.decision.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "severity": self.severity.value,
            "requires_human_confirmation": self.requires_human_confirmation,
        }


@dataclass(frozen=True, slots=True)
class BatchReview:
    results: tuple[ReviewResult, ...]
    overall_decision: Decision

    def to_dict(self) -> dict[str, object]:
        counts = Counter(result.decision.value for result in self.results)
        return {
            "schema": BATCH_SCHEMA,
            "overall_decision": self.overall_decision.value,
            "counts": {
                "allow": counts[Decision.ALLOW.value],
                "confirm": counts[Decision.CONFIRM.value],
                "deny": counts[Decision.DENY.value],
                "total": len(self.results),
            },
            "results": [result.to_dict() for result in self.results],
        }


def _basename(value: str) -> str:
    return PurePosixPath(value).name.casefold()


def _split_shell_payload(tokens: list[str]) -> list[str]:
    if not tokens:
        return []
    if tokens[0] in {"-c", "-lc", "-ec"}:
        if len(tokens) < 2:
            raise PolicyInputError("shell execution flag requires a command payload")
        try:
            return shlex.split(tokens[1], posix=True)
        except ValueError as exc:
            raise PolicyInputError(f"invalid nested shell arguments: {exc}") from exc
    return tokens


def _command_tokens(call: ToolCall) -> list[str]:
    call.validate()
    name = _basename(call.name.strip())
    try:
        arguments = shlex.split(call.args, posix=True)
    except ValueError as exc:
        raise PolicyInputError(f"invalid shell-style arguments: {exc}") from exc

    if name in SHELL_TOOLS:
        return _split_shell_payload(arguments)
    return [name, *arguments]


def _normalized_text(call: ToolCall) -> str:
    return f"{call.name.strip()} {call.args.strip()}".strip()


def _flag_characters(tokens: Sequence[str]) -> set[str]:
    characters: set[str] = set()
    for token in tokens:
        if token == "--":
            break
        if token.startswith("--"):
            if token == "--recursive":
                characters.add("r")
            elif token == "--force":
                characters.add("f")
        elif token.startswith("-"):
            characters.update(token[1:])
    return characters


def _operands(tokens: Sequence[str]) -> list[str]:
    values: list[str] = []
    options_finished = False
    for token in tokens:
        if token == "--":
            options_finished = True
            continue
        if not options_finished and token.startswith("-"):
            continue
        values.append(token)
    return values


def _is_critical_path(value: str) -> bool:
    normalized = value.rstrip("/") or "/"
    if normalized in {"/*", "/."}:
        return True
    return normalized in CRITICAL_ROOTS


def _review_critical_shell(tokens: Sequence[str], text: str) -> ReviewResult | None:
    if FORK_BOMB_RE.search(text):
        return _result(
            Decision.DENY,
            "ASM-DENY-001",
            "fork-bomb pattern would create uncontrolled local processes",
            Severity.CRITICAL,
        )

    if not tokens:
        return None
    command = _basename(tokens[0])
    args = list(tokens[1:])

    if command.startswith("mkfs"):
        return _result(
            Decision.DENY,
            "ASM-DENY-002",
            "filesystem-format command can destroy an entire storage volume",
            Severity.CRITICAL,
        )

    if command == "dd" and any(token.startswith("of=/dev/") for token in args):
        return _result(
            Decision.DENY,
            "ASM-DENY-003",
            "raw device overwrite can irreversibly destroy storage",
            Severity.CRITICAL,
        )

    if command == "rm":
        flags = _flag_characters(args)
        operands = _operands(args)
        if {"r", "f"}.issubset(flags) and any(_is_critical_path(value) for value in operands):
            return _result(
                Decision.DENY,
                "ASM-DENY-004",
                "recursive forced deletion targets a critical absolute path",
                Severity.CRITICAL,
            )
    return None


def _review_confirmation(tokens: Sequence[str], text: str) -> ReviewResult | None:
    if tokens:
        command = _basename(tokens[0])
        args = list(tokens[1:])

        if command == "rm" and "r" in _flag_characters(args):
            return _result(
                Decision.CONFIRM,
                "ASM-CONFIRM-001",
                "recursive deletion requires explicit human confirmation",
                Severity.HIGH,
            )

        if command == "git" and "push" in args:
            force_flags = {"-f", "--force", "--force-with-lease"}
            if force_flags.intersection(args):
                return _result(
                    Decision.CONFIRM,
                    "ASM-CONFIRM-002",
                    "history-rewriting push requires explicit human confirmation",
                    Severity.HIGH,
                )

        if command == "kubectl" and args and args[0] == "delete":
            return _result(
                Decision.CONFIRM,
                "ASM-CONFIRM-003",
                "cluster resource deletion requires explicit human confirmation",
                Severity.HIGH,
            )

        if command == "terraform" and args and args[0] == "destroy":
            return _result(
                Decision.CONFIRM,
                "ASM-CONFIRM-004",
                "infrastructure destruction requires explicit human confirmation",
                Severity.HIGH,
            )

        if command in {"shutdown", "reboot", "poweroff"}:
            return _result(
                Decision.CONFIRM,
                "ASM-CONFIRM-005",
                "host availability change requires explicit human confirmation",
                Severity.HIGH,
            )

    if DROP_TABLE_RE.search(text):
        return _result(
            Decision.CONFIRM,
            "ASM-CONFIRM-006",
            "database table deletion requires explicit human confirmation",
            Severity.HIGH,
        )
    return None


def _result(
    decision: Decision,
    rule_id: str,
    reason: str,
    severity: Severity,
    *,
    call: ToolCall | None = None,
) -> ReviewResult:
    return ReviewResult(
        call=call or ToolCall("internal"),
        decision=decision,
        rule_id=rule_id,
        reason=reason,
        severity=severity,
        requires_human_confirmation=decision is Decision.CONFIRM,
    )


def review_tool_call(call: ToolCall) -> ReviewResult:
    """Review one proposed call without executing it or claiming semantic safety."""

    tokens = _command_tokens(call)
    text = _normalized_text(call)

    result = _review_critical_shell(tokens, text)
    if result is None:
        result = _review_confirmation(tokens, text)
    if result is None:
        result = _result(
            Decision.ALLOW,
            "ASM-ALLOW-DEFAULT",
            "no configured policy rule matched the proposed call",
            Severity.NONE,
        )
    return ReviewResult(
        call=call,
        decision=result.decision,
        rule_id=result.rule_id,
        reason=result.reason,
        severity=result.severity,
        requires_human_confirmation=result.requires_human_confirmation,
    )


def review_batch(calls: Sequence[ToolCall]) -> BatchReview:
    """Review calls in order and summarize the strongest required disposition."""

    results = tuple(review_tool_call(call) for call in calls)
    overall = max(
        (result.decision for result in results),
        key=lambda decision: _DECISION_RANK[decision],
        default=Decision.ALLOW,
    )
    return BatchReview(results=results, overall_decision=overall)
