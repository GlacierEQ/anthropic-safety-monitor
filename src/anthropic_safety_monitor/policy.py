from __future__ import annotations

import posixpath
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
SHELL_EXECUTION_FLAGS = frozenset({"-c", "-ec", "-lc"})
SHELL_SEPARATORS = frozenset({";", "&&", "||", "|", "&", "\n"})
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
DYNAMIC_SHELL_RE = re.compile(r"\$\(|`")
KUBECTL_GLOBAL_VALUE_OPTIONS = frozenset(
    {
        "--as",
        "--as-group",
        "--cache-dir",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--cluster",
        "--context",
        "--kubeconfig",
        "--namespace",
        "--password",
        "--profile",
        "--profile-output",
        "--request-timeout",
        "--server",
        "--tls-server-name",
        "--token",
        "--user",
        "--username",
        "-n",
        "-s",
    }
)
SUDO_VALUE_OPTIONS = frozenset(
    {
        "--chdir",
        "--close-from",
        "--command-timeout",
        "--group",
        "--host",
        "--prompt",
        "--role",
        "--type",
        "--user",
        "-C",
        "-D",
        "-g",
        "-h",
        "-p",
        "-R",
        "-T",
        "-t",
        "-u",
    }
)
ENV_VALUE_OPTIONS = frozenset({"--chdir", "--split-string", "--unset", "-C", "-S", "-u"})


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


def _shell_tokens(payload: str) -> list[str]:
    try:
        lexer = shlex.shlex(payload, posix=True, punctuation_chars=";&|\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError as exc:
        raise PolicyInputError(f"invalid shell arguments: {exc}") from exc


def _shell_payload(call: ToolCall) -> str:
    try:
        arguments = shlex.split(call.args, posix=True)
    except ValueError as exc:
        raise PolicyInputError(f"invalid shell-style arguments: {exc}") from exc

    for index, argument in enumerate(arguments):
        if argument in SHELL_EXECUTION_FLAGS:
            if index + 1 >= len(arguments):
                raise PolicyInputError("shell execution flag requires a command payload")
            return arguments[index + 1]
    return call.args


def _split_segments(tokens: Sequence[str]) -> tuple[tuple[str, ...], ...]:
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in SHELL_SEPARATORS:
            if segments[-1]:
                segments.append([])
            continue
        segments[-1].append(token)
    return tuple(tuple(segment) for segment in segments if segment)


def _command_segments(call: ToolCall) -> tuple[tuple[str, ...], ...]:
    call.validate()
    name = _basename(call.name.strip())
    if name in SHELL_TOOLS:
        return _split_segments(_shell_tokens(_shell_payload(call)))

    try:
        arguments = shlex.split(call.args, posix=True)
    except ValueError as exc:
        raise PolicyInputError(f"invalid shell-style arguments: {exc}") from exc
    return ((name, *arguments),)


def _skip_options(
    tokens: Sequence[str],
    *,
    value_options: frozenset[str],
    assignments: bool = False,
) -> list[str]:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return list(tokens[index + 1 :])
        if assignments and "=" in token and not token.startswith("-"):
            index += 1
            continue
        option_name = token.split("=", 1)[0]
        if option_name in value_options:
            index += 1 if "=" in token else 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return list(tokens[index:])
    return []


def _strip_wrappers(tokens: Sequence[str]) -> list[str]:
    normalized = list(tokens)
    while normalized:
        command = _basename(normalized[0])
        if command in {"command", "exec", "nohup"}:
            normalized = normalized[1:]
            continue
        if command == "env":
            normalized = _skip_options(
                normalized[1:],
                value_options=ENV_VALUE_OPTIONS,
                assignments=True,
            )
            continue
        if command == "sudo":
            normalized = _skip_options(
                normalized[1:],
                value_options=SUDO_VALUE_OPTIONS,
            )
            continue
        break
    return normalized


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
    if not value.startswith("/"):
        return False
    normalized = posixpath.normpath(value)
    if normalized in {"/*", "/."}:
        return True
    return normalized in CRITICAL_ROOTS


def _subcommand(tokens: Sequence[str], *, value_options: frozenset[str]) -> str | None:
    remaining = _skip_options(tokens, value_options=value_options)
    return remaining[0].casefold() if remaining else None


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

        if (
            command == "kubectl"
            and _subcommand(
                args,
                value_options=KUBECTL_GLOBAL_VALUE_OPTIONS,
            )
            == "delete"
        ):
            return _result(
                Decision.CONFIRM,
                "ASM-CONFIRM-003",
                "cluster resource deletion requires explicit human confirmation",
                Severity.HIGH,
            )

        if (
            command == "terraform"
            and _subcommand(
                args,
                value_options=frozenset({"-chdir"}),
            )
            == "destroy"
        ):
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


def _strongest(results: Sequence[ReviewResult]) -> ReviewResult:
    return max(results, key=lambda result: _DECISION_RANK[result.decision])


def review_tool_call(call: ToolCall) -> ReviewResult:
    """Review one proposed call without executing it or claiming semantic safety."""

    segments = _command_segments(call)
    candidates: list[ReviewResult] = []

    if _basename(call.name.strip()) in SHELL_TOOLS:
        payload = _shell_payload(call)
        if FORK_BOMB_RE.search(payload):
            candidates.append(
                _result(
                    Decision.DENY,
                    "ASM-DENY-001",
                    "fork-bomb pattern would create uncontrolled local processes",
                    Severity.CRITICAL,
                )
            )
        if DYNAMIC_SHELL_RE.search(payload):
            candidates.append(
                _result(
                    Decision.CONFIRM,
                    "ASM-CONFIRM-007",
                    "dynamic shell expansion requires explicit human confirmation",
                    Severity.HIGH,
                )
            )

    for raw_segment in segments:
        segment = _strip_wrappers(raw_segment)
        if not segment:
            continue
        text = " ".join(segment)
        result = _review_critical_shell(segment, text)
        if result is None:
            result = _review_confirmation(segment, text)
        if result is None:
            result = _result(
                Decision.ALLOW,
                "ASM-ALLOW-DEFAULT",
                "no configured policy rule matched the proposed call",
                Severity.NONE,
            )
        candidates.append(result)

    result = (
        _strongest(candidates)
        if candidates
        else _result(
            Decision.ALLOW,
            "ASM-ALLOW-DEFAULT",
            "no configured policy rule matched the proposed call",
            Severity.NONE,
        )
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
