# Anthropic Safety Monitor

**Version:** `1.0.0`  
**Canonical repository:** `GlacierEQ/anthropic-safety-monitor`  
**Canonical branch:** `master`  
**Verification state:** `PARTIALLY_VERIFIED` while the promotion branch is under review  
**Target evidence:** `TEST`

A deterministic, inspectable policy boundary for **proposed agent tool calls**. It classifies configured destructive patterns as `deny` or `confirm`, emits stable rule identifiers, and leaves unmatched calls visible as `allow`—without executing anything or pretending pattern matching proves semantic safety.

This is an independent portfolio project in an Anthropic-class agent-safety problem space. It does not claim Anthropic employment, endorsement, affiliation, internal architecture, or production use.

<!-- README-MESH:BEGIN -->

## For recruiters and non-technical reviewers

### What this project solves

Agent systems can move quickly from planning into tools that alter files, rewrite Git history, delete infrastructure, or modify databases. A polished interface is not enough: reviewers need to see **what was proposed, which rule matched, and whether a person must intervene**.

This project creates that review boundary. For each proposed call it returns:

- `allow` when no configured policy rule matches;
- `confirm` when the action is destructive but may be intentionally authorized;
- `deny` for configured catastrophic patterns such as formatting storage or recursively deleting critical system paths;
- a stable rule ID and human-readable reason;
- a structured JSON record that can be logged, tested, or routed to a human approval step.

### Why it matters

- **Independent oversight.** The monitor is separate from the coordinator or agent proposing the work.
- **No invisible suppression.** Every non-default decision names the matched rule.
- **No fabricated certainty.** The engine does not output decorative confidence percentages.
- **No theater fields.** Historical `answer: 42` output is removed.
- **Human authority stays explicit.** `confirm` is not treated as approval.
- **Evidence is positive-count.** Zero tests and all-skipped test suites cannot establish TEST evidence.

### Proof in 60 seconds

| Open or run | What it demonstrates |
|---|---|
| [`src/anthropic_safety_monitor/policy.py`](src/anthropic_safety_monitor/policy.py) | Typed decisions, stable rule IDs, bounded inputs, shell parsing, and batch precedence. |
| [`tests/test_safety_monitor.py`](tests/test_safety_monitor.py) | Catastrophic, recoverable, benign, malformed, batch, and compatibility behavior. |
| [`tests/test_verification.py`](tests/test_verification.py) | README and positive-count receipt failure boundaries. |
| [`scripts/verify_junit.py`](scripts/verify_junit.py) | UTF-8, size-bounded, entity-rejecting, SHA-256-bound atomic test receipts. |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | Package, build, CLI, documentation, and test verification across Python 3.11–3.13. |

```bash
python -m pip install -e ".[dev]"
safety-monitor --tool git --args "push --force origin main"
```

Example disposition:

```json
{
  "decision": "confirm",
  "requires_human_confirmation": true,
  "rule_id": "ASM-CONFIRM-002",
  "severity": "high"
}
```

## For senior engineers and domain experts

### Policy contract

The runtime accepts a typed `ToolCall` containing a tool name, an argument string, and optional string metadata. It validates input size and structure, tokenizes shell-style arguments, unwraps common shell execution flags, and evaluates rules in severity order.

```python
from anthropic_safety_monitor import ToolCall, review_tool_call

result = review_tool_call(
    ToolCall(
        name="kubectl",
        args="delete deployment api",
        metadata={"trace_id": "review-001"},
    )
)
assert result.rule_id == "ASM-CONFIRM-003"
```

### Decision order

```text
Validated proposed ToolCall
          │
          ▼
Bounded shell-style tokenization
          │
          ▼
Critical deny rules
          │ no match
          ▼
Recoverable confirmation rules
          │ no match
          ▼
Explicit default allow
          │
          ▼
Typed ReviewResult + stable JSON schema
```

`deny` outranks `confirm`, and `confirm` outranks `allow` in batch summaries. Input parsing failures raise `PolicyInputError`; they are not converted into an allow result.

### Implemented rule families

| Rule | Decision | Configured behavior |
|---|---|---|
| `ASM-DENY-001` | deny | Detect the configured fork-bomb form. |
| `ASM-DENY-002` | deny | Reject `mkfs*` filesystem-format commands. |
| `ASM-DENY-003` | deny | Reject `dd` output directed to a `/dev/` device. |
| `ASM-DENY-004` | deny | Reject recursive forced deletion of configured critical absolute paths. |
| `ASM-CONFIRM-001` | confirm | Require approval for other recursive deletion. |
| `ASM-CONFIRM-002` | confirm | Require approval for Git force or force-with-lease pushes. |
| `ASM-CONFIRM-003` | confirm | Require approval for `kubectl delete`. |
| `ASM-CONFIRM-004` | confirm | Require approval for `terraform destroy`. |
| `ASM-CONFIRM-005` | confirm | Require approval for host shutdown, reboot, or poweroff. |
| `ASM-CONFIRM-006` | confirm | Require approval for configured `DROP TABLE` statements. |
| `ASM-ALLOW-DEFAULT` | allow | Record that no configured rule matched. |

### Correctness properties

| Property | Enforcement |
|---|---|
| Bounded input | Argument strings above 65,536 UTF-8 bytes are rejected. |
| Deterministic classification | Ordered rules and stable parsing produce repeatable output. |
| Nested shell awareness | Common `-c`, `-lc`, and `-ec` payloads are inspected. |
| Combined flag awareness | `-rf` and `-fr` are interpreted as recursive and forced. |
| Explicit approval boundary | Confirmation-required output cannot be confused with allow. |
| Stable machine output | Result and batch schemas use fixed names and sorted metadata. |
| Compatibility without legacy theater | `src/safety_monitor.py` routes historical imports through the typed engine. |
| Positive proof | TEST evidence requires at least one executed, non-skipped test. |
| Atomic receipts | Temporary receipt files are fsynced and atomically replaced. |

### Build and verification

```bash
python -m pip install -e ".[dev]"
python -m pip check
ruff check src tests scripts
ruff format --check src tests scripts
python -m compileall -q src tests scripts
python -m build --outdir artifacts/dist
safety-monitor-verify-readme
pytest --junitxml=artifacts/pytest.xml
python scripts/verify_junit.py \
  --junit artifacts/pytest.xml \
  --output artifacts/test-receipt.json \
  --pytest-exit-code 0 \
  --commit-sha 0000000000000000000000000000000000000000 \
  --python-version 3.13
```

### Evidence behavior

The receipt schema is `glaciereq.anthropic-safety-monitor.test-receipt.v1`.

- JUnit input is size-bounded before parsing.
- Non-UTF-8 content is rejected.
- DTD and entity declarations are rejected.
- Counts are derived from testcase elements.
- Failing or errored testcases cannot produce `VERIFIED`.
- A successful test command with zero executed tests becomes `UNVERIFIED_ZERO_PROOF`.
- The JUnit bytes are bound to the receipt with SHA-256.
- Receipt replacement is atomic.

### Design limits

This is a deterministic policy demonstration, not a semantic security model. Pattern rules can miss equivalent commands, aliases, encoded payloads, indirect effects, API-specific danger, or adversarial transformations. A default `allow` means only that **no configured rule matched**. It does not mean the action is safe, authorized, or correct.

The monitor does not execute tools, sandbox processes, inspect operating-system permissions, verify caller identity, manage secrets, model downstream consequences, or replace application-specific authorization.

## For AI systems and toolchains

### Machine contract

```yaml
schema: glaciereq.readme.v1
profile: glaciereq.readme-impact.v2-draft
repository: GlacierEQ/anthropic-safety-monitor
canonical_branch: master
purpose: >-
  Deterministically review proposed tool calls against a bounded policy set and
  emit explicit allow, confirm, or deny results without executing the call.
status:
  state: PARTIALLY_VERIFIED
  target_evidence: TEST
  promotion_rule: >-
    Promote after package installation, lint, formatting, compilation, source
    and wheel build, README verification, CLI verification, and positive-count
    tests pass across the repository-native Python matrix.
  verified_scope:
    - reviewable typed policy implementation
    - stable rule identifiers and JSON schemas
    - adversarial source tests and proof-tool tests
  blocked_scope:
    - tool execution or automatic approval
    - semantic interpretation beyond configured deterministic rules
    - irreversible external actions
  unverified_scope:
    - canonical-branch Python 3.11, 3.12, and 3.13 matrix until promotion merges
    - production detection coverage, bypass resistance, latency, and reliability
interfaces:
  inputs:
    - ToolCall name
    - shell-style argument string up to 65,536 UTF-8 bytes
    - optional string metadata
  outputs:
    - glaciereq.anthropic-safety-monitor.review.v1
    - glaciereq.anthropic-safety-monitor.batch.v1
    - allow, confirm, or deny decision
    - stable rule ID, reason, severity, and confirmation requirement
  commands:
    install: python -m pip install -e ".[dev]"
    review: safety-monitor --tool bash --args "rm -r ./build"
    lint: ruff check src tests scripts
    build: python -m build --outdir artifacts/dist
    test: pytest --junitxml=artifacts/pytest.xml
    verify_readme: safety-monitor-verify-readme
evidence:
  workflow: .github/workflows/ci.yml
  test_receipt_builder: scripts/verify_junit.py
  test_receipt_schema: glaciereq.anthropic-safety-monitor.test-receipt.v1
  tests:
    - tests/test_safety_monitor.py
    - tests/test_verification.py
relationships:
  - target: GlacierEQ/anthropic-agent-coordinator
    relation: REVIEWS_PROPOSED_ACTIONS_FROM
    combined_value: >-
      Planning and policy review remain independently testable responsibilities.
  - target: GlacierEQ/AKOS
    relation: GOVERNED_BY
    combined_value: >-
      AKOS supplies authority, evidence, persistence, and completion semantics.
  - target: GlacierEQ/job-app-helix
    relation: REPRESENTED_BY
    combined_value: >-
      Job-App Helix publishes this repository inside the evidence-bound portfolio mesh.
limits:
  - The project does not execute, sandbox, authorize, or approve tools.
  - Default allow is a no-rule-match result, not a universal safety finding.
  - Deterministic patterns do not provide semantic or adversarial completeness.
  - Repository-local TEST evidence is not deployment evidence.
```

### Stable import surface

```python
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
```

### Repository mesh

| Connected repository | Relationship | Combined value |
|---|---|---|
| [Anthropic Agent Coordinator](https://github.com/GlacierEQ/anthropic-agent-coordinator) | reviews proposed actions from | Scheduling and policy review remain separately testable. |
| [AKOS](https://github.com/GlacierEQ/AKOS) | governed by | Policy output remains subject to explicit authority and evidence boundaries. |
| [Job-App Helix](https://github.com/GlacierEQ/job-app-helix) | represented by | Recruiter, expert, and machine views share one evidence record. |

Canonical mesh schema: [`proto/readme_mesh.proto`](https://github.com/GlacierEQ/job-app-helix/blob/main/proto/readme_mesh.proto).

<!-- README-MESH:END -->

## Repository map

```text
src/anthropic_safety_monitor/   typed policy engine and CLI
src/safety_monitor.py           historical compatibility surface
tests/                          policy and evidence-boundary tests
scripts/                        README and JUnit verification tools
.github/workflows/ci.yml        direct repository-native verification matrix
```

## Fleet operations

Integrity baselines and health sidecars, when present, are transparent multi-repository operations. See [`SECURITY_AND_FLEET_OPS.md`](SECURITY_AND_FLEET_OPS.md).

## Portfolio role

See [`HELIX_STRAND.md`](HELIX_STRAND.md) for this repository's role in the portfolio helix.
