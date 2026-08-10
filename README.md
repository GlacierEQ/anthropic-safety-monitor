<<<<<<< HEAD
# Anthropic Safety Monitor

**Version:** `1.0.0`  
**Canonical repository:** `GlacierEQ/anthropic-safety-monitor`  
**Canonical branch:** `master`  
**Verification state:** `VERIFIED` at repository-native `TEST` evidence  
**Canonical promotion:** `c7ab52e0e70a5cd449f9335f90030059d254325f`

A deterministic, inspectable policy boundary for **proposed agent tool calls**. It returns `allow`, `confirm`, or `deny` with stable rule identifiers and explicit reasons—without executing the proposed action or pretending deterministic pattern matching proves universal safety.

This is an independent portfolio project in an Anthropic-class agent-safety problem space. It does not claim Anthropic employment, endorsement, affiliation, internal architecture, or production use.

<!-- README-MESH:BEGIN -->

## For recruiters and non-technical reviewers

### What this project proves

Agent systems can move from planning into tools that delete files, rewrite Git history, destroy infrastructure, or modify databases. This project inserts a reviewable boundary between a proposed action and execution.

For every reviewed call it records:

- the proposed tool and arguments;
- an `allow`, `confirm`, or `deny` disposition;
- the exact rule that matched;
- a human-readable reason and severity;
- whether explicit human confirmation is still required.

The public implementation removes two forms of evidence theater from the original toy script: the sentinel `answer: 42` field and decorative confidence percentages.

### Why it matters

- **Catastrophic patterns are explicit.** Filesystem formatting, raw-device overwrite, fork bombs, and recursive forced deletion of critical roots are denied.
- **Intentional destruction remains human-controlled.** Recursive deletion, Git force pushes, Kubernetes deletion, Terraform destruction, host power changes, and `DROP TABLE` require confirmation.
- **Shell wrappers do not hide later commands.** Chained commands and supported `sudo` or `env` prefixes are reviewed segment by segment.
- **No silent proof inflation.** Zero tests and all-skipped suites cannot establish `TEST` evidence.
- **Every claim has a boundary.** Default `allow` means only that no configured rule matched.

### Verified evidence

The exact promotion candidate passed the direct read-only matrix on Python 3.11, 3.12, and 3.13:

| Gate | Result |
|---|---:|
| Package install and dependency check | PASS |
| Ruff lint and formatter check | PASS |
| Bytecode compilation | PASS |
| Source and wheel builds | PASS |
| README and CLI contracts | PASS |
| Tests per interpreter | 51 passed |
| Total matrix executions | 153 passed |
| Failures / errors / skips | 0 / 0 / 0 |
| Review threads | All resolved |

Evidence surfaces:

- [`receipts/wave-1-test-verification-2026-07-31.json`](receipts/wave-1-test-verification-2026-07-31.json)
- [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
- [`tests/test_safety_monitor.py`](tests/test_safety_monitor.py)
- [`tests/test_verification.py`](tests/test_verification.py)

### Try the boundary

```bash
python -m pip install -e ".[dev]"
safety-monitor --tool git --args "push --force origin main"
=======
# Anthropic Safety Monitor — Action Boundary & Guardrail Governor 🛡️

> **Real-time action boundary checker and safety guardrail enforcer for autonomous agents.**

[![Python](https://img.shields.io/badge/Python-3.9+-blue)]()
[![Rust](https://img.shields.io/badge/Rust-Safety%20Critical-orange)]()
[![Domain](https://img.shields.io/badge/Domain-AI%20Safety%20%26%20Alignment-red)]()

---

## 🎯 For Recruiters & Hiring Managers

This repository implements a **safety boundary checker** — enforcing hard limits on autonomous agent actions to prevent unauthorized system mutations or runaway loops. It demonstrates:

- **Action boundary validation** with configurable rate and mutation caps
- **Rust memory-safe safety governor** executing zero-cost compile-time checks
- **Audit logging** capturing all agent action requests and enforcement decisions
- **Real-time kill switch** capability for rogue agent containment

**Why this matters**: Deploying autonomous agents into production environments requires strict, deterministic safety guardrails that run outside the model's self-governance.

---

## 🔬 For Engineers & Technical Reviewers

### Architecture

```
Agent Action ──→ Safety Monitor Guard (Rust) ──→ Allow / Deny Decision
                         │
                 Boundary Checklist
            (File Mut Caps, Rate Limits)
```

### Core Components

| Component | Language | Purpose |
|---|---|---|
| `src/safety_monitor.py` | Python | Guardrail policy management and event dispatcher |
| `src/boundary_checker.rs` | Rust | Zero-overhead compiled boundary enforcer |
| `tests/` | Python | Adversarial test cases verifying boundary containment |

---

## 🤖 ML/AI & Programmatic Mesh Integration

- **MCP Tool**: `check_safety_boundary()` — real-time safety verification for agent tool calls
- **Mastermind Sidecar**: Publishes security policy violations to APEX Highway mesh
- **SHA-256 Integrity**: Verified via `.integrity/file_hashes.json`

```rust
let checker = ActionBoundaryChecker::new(10);
assert!(checker.validate_mutation());
>>>>>>> a66a2a5 (docs(readme): upgrade to 3-section recruiter/engineer/mesh structure & update SHA-256 baseline)
```

The result is structured JSON with `ASM-CONFIRM-002`, not an execution request.

<<<<<<< HEAD
## For senior engineers and domain experts

### Architecture

```text
Proposed ToolCall
      │
      ▼
Input and metadata validation
      │
      ▼
Bounded shell parsing
      │
      ▼
Command segmentation and wrapper normalization
      │
      ├── critical deny rules
      ├── confirmation rules
      └── explicit default allow
      │
      ▼
Typed ReviewResult / BatchReview
      │
      ▼
JSON, tests, receipts, or human approval workflow
```

The package exposes immutable dataclasses and closed enums through `anthropic_safety_monitor`. The historical `safety_monitor` module remains a compatibility shim that routes through the same typed engine.

### Rule families

| Rule | Decision | Configured behavior |
|---|---|---|
| `ASM-DENY-001` | deny | Fork-bomb pattern |
| `ASM-DENY-002` | deny | `mkfs*` filesystem formatting |
| `ASM-DENY-003` | deny | `dd` output to `/dev/*` |
| `ASM-DENY-004` | deny | Recursive forced deletion of normalized critical roots |
| `ASM-CONFIRM-001` | confirm | Other recursive deletion |
| `ASM-CONFIRM-002` | confirm | Git force or force-with-lease push |
| `ASM-CONFIRM-003` | confirm | `kubectl delete`, including supported global options |
| `ASM-CONFIRM-004` | confirm | `terraform destroy`, including `-chdir` |
| `ASM-CONFIRM-005` | confirm | Shutdown, reboot, or poweroff |
| `ASM-CONFIRM-006` | confirm | `DROP TABLE` |
| `ASM-CONFIRM-007` | confirm | Dynamic shell expansion |
| `ASM-ALLOW-DEFAULT` | allow | No configured rule matched |

### Security hardening verified in review

The promotion review identified and closed concrete bypasses:

- shell commands chained with `;`, `&&`, `||`, `|`, `&`, or newline;
- destructive commands hidden behind `sudo`, `env`, `command`, `exec`, or `nohup`;
- critical absolute paths expressed with `..` components;
- Kubernetes and Terraform subcommands preceded by global options;
- JUnit files enlarged between a separate stat and unbounded read;
- unsafe XML DTD, entity, or external-reference processing;
- receipts bound to GitHub’s synthetic merge SHA instead of the reviewed PR head.

### Verification model

`scripts/verify_junit.py`:

- opens the report once and reads at most `MAX_JUNIT_BYTES + 1`;
- validates UTF-8;
- rejects DTD and entity markers before parsing;
- uses `defusedxml` with DTD, entity, and external references forbidden;
- derives counts from testcase elements;
- requires at least one executed non-skipped test;
- binds the report bytes with SHA-256;
- writes receipts through fsync and atomic replacement.

Receipt schema: `glaciereq.anthropic-safety-monitor.test-receipt.v1`.

### Build and test

```bash
python -m pip install -e ".[dev]"
python -m pip check
ruff check src tests scripts
ruff format --check src tests scripts
python -m compileall -q src tests scripts
python -m build --outdir artifacts/dist
safety-monitor-verify-readme
pytest --junitxml=artifacts/pytest.xml
```

### Engineering limits

This is a deterministic policy engine, not a semantic security model. It can miss aliases, encodings, indirect API effects, runtime state, permission context, and adversarial transformations outside the configured parser and rules. It does not execute tools, sandbox processes, authenticate callers, manage secrets, or authorize irreversible actions.

## For AI systems and toolchains

### Machine contract

```yaml
schema: glaciereq.readme.v1
profile: glaciereq.readme-impact.v2
repository: GlacierEQ/anthropic-safety-monitor
canonical_branch: master
purpose: >-
  Review proposed tool calls against a bounded deterministic policy set and emit
  explicit allow, confirm, or deny results without executing the call.
status:
  state: VERIFIED
  evidence_level: TEST
  canonical_commit: c7ab52e0e70a5cd449f9335f90030059d254325f
  matrix:
    python: ["3.11", "3.12", "3.13"]
    tests_per_version: 51
    total_executions: 153
    failures: 0
    errors: 0
    skipped: 0
  blocked_scope:
    - tool execution or automatic approval
    - semantic safety claims beyond configured deterministic rules
    - irreversible external actions
  unverified_scope:
    - production detection coverage and adversarial completeness
    - deployment latency, scale, and operational reliability
interfaces:
  inputs:
    - ToolCall name
    - shell-style argument string up to 65,536 UTF-8 bytes
    - optional string metadata
  outputs:
    - glaciereq.anthropic-safety-monitor.review.v1
    - glaciereq.anthropic-safety-monitor.batch.v1
    - allow, confirm, or deny
    - rule ID, reason, severity, and confirmation requirement
  commands:
    install: python -m pip install -e ".[dev]"
    review: safety-monitor --tool bash --args "rm -r ./build"
    lint: ruff check src tests scripts
    build: python -m build --outdir artifacts/dist
    test: pytest --junitxml=artifacts/pytest.xml
    verify_readme: safety-monitor-verify-readme
evidence:
  workflow: .github/workflows/ci.yml
  receipt: receipts/wave-1-test-verification-2026-07-31.json
  receipt_builder: scripts/verify_junit.py
  receipt_schema: glaciereq.anthropic-safety-monitor.test-receipt.v1
relationships:
  - target: GlacierEQ/anthropic-agent-coordinator
    relation: REVIEWS_PROPOSED_ACTIONS_FROM
  - target: GlacierEQ/AKOS
    relation: GOVERNED_BY
  - target: GlacierEQ/job-app-helix
    relation: REPRESENTED_BY
limits:
  - Default allow means no configured match, not universal safety.
  - Confirmation is not authorization.
  - Repository TEST evidence is not deployment evidence.
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

### Repository relationships

- **Anthropic Agent Coordinator:** proposes deterministic plans; this repository independently reviews proposed tool calls.
- **AKOS:** supplies authority, evidence, persistence, and completion semantics.
- **Job-App Helix:** publishes the project in the evidence-bound portfolio mesh.

<!-- README-MESH:END -->

## Repository map

```text
src/anthropic_safety_monitor/   typed policy engine and CLI
src/safety_monitor.py           historical compatibility surface
tests/                          policy and verification regression tests
scripts/                        README and JUnit evidence tools
receipts/                       immutable promotion evidence
.github/workflows/ci.yml        direct repository-native verification matrix
=======
## ⚡ Quick Start

```bash
python3 src/safety_monitor.py
python3 tests/test_boundary_checker.py
>>>>>>> a66a2a5 (docs(readme): upgrade to 3-section recruiter/engineer/mesh structure & update SHA-256 baseline)
```
