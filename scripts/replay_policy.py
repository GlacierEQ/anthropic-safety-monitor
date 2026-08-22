#!/usr/bin/env python3
"""Replay the committed policy corpus and write a deterministic semantic-drift receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from anthropic_safety_monitor.replay import load_scenarios, replay_scenarios


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("verification/policy_replay_scenarios.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    scenarios = load_scenarios(args.corpus)
    report = replay_scenarios(scenarios)
    payload = report.as_dict()
    payload["report_fingerprint"] = report.fingerprint
    payload["repository"] = os.environ.get(
        "GITHUB_REPOSITORY", "GlacierEQ/anthropic-safety-monitor"
    )
    payload["commit"] = os.environ.get("VERIFIED_SHA", os.environ.get("GITHUB_SHA", "local"))
    payload["generated_at"] = datetime.now(timezone.utc).isoformat()
    payload["claims_not_established"] = [
        "Anthropic affiliation or internal policy",
        "production Anthropic safety enforcement",
        "provider-side tool execution",
        "policy fitness beyond the explicit committed replay corpus",
    ]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.write_bytes(encoded)
    artifact_sha = hashlib.sha256(encoded).hexdigest()
    print(
        json.dumps(
            {
                "schema": "glaciereq.anthropic-safety-monitor.replay-receipt.v1",
                "passed": report.passed,
                "scenario_count": len(report.entries),
                "drift_count": report.drift_count,
                "baseline_fingerprint": report.baseline_fingerprint,
                "report_fingerprint": report.fingerprint,
                "artifact_sha256": artifact_sha,
                "artifact": str(args.output),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
