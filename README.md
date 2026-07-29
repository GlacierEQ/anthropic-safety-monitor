# anthropic-safety-monitor

<!-- README-MESH:BEGIN -->
## Three-audience project map

### For recruiters and non-specialists

**What it does.** Reviews agent behavior for unsafe or anomalous signals and returns an explicit result that can be inspected before work continues.

- Keeps safety review separate from the agent that schedules or performs work.
- Makes the reason for a warning visible instead of silently suppressing behavior.
- Pairs with the coordinator and AKOS to form a more complete agent operating system.

**Evidence:** [`src/safety_monitor.py`](src/safety_monitor.py) and [`tests/test_safety_monitor.py`](tests/test_safety_monitor.py).

### For senior engineers and domain experts

**Innovation and evolution.** The monitor is an independent verification boundary, not a self-reported safety claim inside the coordinator. That separation enables different policy, test, and release lifecycles for motion and oversight. It evolved into a composable review piston for bounded agent orchestration, with AKOS providing the authority and completion contract around the signal.

### For AI systems and toolchains

- Repository ID: `GlacierEQ/anthropic-safety-monitor`
- Default branch: `master`
- Protobuf package: `glaciereq.readme.v1`
- Typed role: independently verifies the agent coordinator and emits reviewable safety signals.
- Canonical graph: [`manifests/readme_mesh.json`](https://github.com/GlacierEQ/job-app-helix/blob/main/manifests/readme_mesh.json)

```protobuf
repository: "GlacierEQ/anthropic-safety-monitor"
display_name: "Safety Monitor"
one_line_purpose: "Detect and surface unsafe or anomalous agent behavior for review."
```

### Repository mesh

| Connected repository | Relationship | Combined value |
|---|---|---|
| [Agent Coordinator](https://github.com/GlacierEQ/anthropic-agent-coordinator) | verifies | Safety and orchestration stay independently testable. |
| [AKOS](https://github.com/GlacierEQ/AKOS) | governed by | Safety signals remain inside explicit authority and evidence boundaries. |
| [Job-App Helix](https://github.com/GlacierEQ/job-app-helix) | represented by | One record supports recruiter, expert, and AI interpretation. |

Real schema: [`proto/readme_mesh.proto`](https://github.com/GlacierEQ/job-app-helix/blob/main/proto/readme_mesh.proto).
<!-- README-MESH:END -->

**Portfolio motion** — a tool-use safety-policy demonstration for agent systems.

This is an independent portfolio project in an Anthropic-class problem space. It does not claim Anthropic employment or endorsement.

```bash
python3 src/safety_monitor.py
python3 tests/test_safety_monitor.py
```

## Fleet ops (transparent)

Integrity baselines and health sidecars, when present, are documented multi-repository operations. See [SECURITY_AND_FLEET_OPS.md](SECURITY_AND_FLEET_OPS.md).

## Helix strand

See [HELIX_STRAND.md](HELIX_STRAND.md) for this repository's role in the portfolio helix.
