from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from .policy import PolicyInputError, ToolCall, review_tool_call


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safety-monitor",
        description="Review one proposed tool call without executing it.",
    )
    parser.add_argument("--tool", required=True, help="Tool or executable name")
    parser.add_argument("--args", default="", help="Proposed argument string")
    parser.add_argument(
        "--metadata",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Optional repeatable string metadata",
    )
    return parser


def _metadata(values: Sequence[str]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        if not separator or not key.strip():
            raise PolicyInputError("metadata must use KEY=VALUE")
        metadata[key.strip()] = item
    return metadata


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    namespace = parser.parse_args(argv)
    try:
        result = review_tool_call(
            ToolCall(
                name=namespace.tool,
                args=namespace.args,
                metadata=_metadata(namespace.metadata),
            )
        )
    except PolicyInputError as exc:
        parser.error(str(exc))
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
