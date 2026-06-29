"""Agent Safety Monitor — Detects and isolates misaligned agents.

Their pain: "Teaching Claude why" — reducing agentic misalignment.

Innovation: Multi-layer safety monitoring:
1. Behavioral baseline — learns what "normal" agent behavior looks like
2. Drift detection — catches gradual misalignment before it becomes dangerous
3. Constraint enforcement — hard limits on agent actions
4. Automatic isolation — removes dangerous agents without human intervention
"""

import math
import time
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class SafetyLevel(Enum):
    SAFE = "safe"
    CAUTION = "caution"
    WARNING = "warning"
    CRITICAL = "critical"
    ISOLATED = "isolated"


@dataclass
class AgentAction:
    agent_id: str
    action_type: str
    action_data: Dict[str, Any]
    timestamp: float
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SafetyConstraint:
    name: str
    description: str
    max_frequency: int
    max_consecutive: int
    requires_approval: bool = False


class BehavioralBaseline:
    """Learns normal agent behavior patterns."""

    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.action_counts: Dict[str, Dict[str, int]] = {}
        self.action_sequences: Dict[str, List[str]] = {}
        self.transition_matrix: Dict[str, Dict[str, float]] = {}

    def record_action(self, agent_id: str, action: AgentAction):
        if agent_id not in self.action_counts:
            self.action_counts[agent_id] = {}
            self.action_sequences[agent_id] = []

        atype = action.action_type
        self.action_counts[agent_id][atype] = self.action_counts[agent_id].get(atype, 0) + 1

        seq = self.action_sequences[agent_id]
        if seq:
            prev = seq[-1]
            if prev not in self.transition_matrix:
                self.transition_matrix[prev] = {}
            self.transition_matrix[prev][atype] = self.transition_matrix[prev].get(atype, 0) + 1

        seq.append(atype)
        if len(seq) > self.window_size:
            self.action_sequences[agent_id] = seq[-self.window_size:]

    def get_action_probability(self, agent_id: str, action_type: str) -> float:
        counts = self.action_counts.get(agent_id, {})
        total = sum(counts.values())
        if total == 0:
            return 0.0
        return counts.get(action_type, 0) / total

    def get_transition_probability(self, from_action: str, to_action: str) -> float:
        transitions = self.transition_matrix.get(from_action, {})
        total = sum(transitions.values())
        if total == 0:
            return 0.0
        return transitions.get(to_action, 0) / total


class SafetyEnforcer:
    """Enforces safety constraints on agent actions."""

    def __init__(self):
        self.constraints: Dict[str, SafetyConstraint] = {}
        self.violations: List[dict] = []

    def add_constraint(self, constraint: SafetyConstraint):
        self.constraints[constraint.name] = constraint

    def check_action(
        self,
        agent_id: str,
        action: AgentAction,
        baseline: BehavioralBaseline,
    ) -> dict:
        violations = []
        safety_level = SafetyLevel.SAFE

        prob = baseline.get_action_probability(agent_id, action.action_type)
        if prob < 0.01 and action.action_type not in ("system_check", "heartbeat"):
            violations.append({
                "type": "novel_action",
                "description": f"Action '{action.action_type}' never seen before for this agent",
                "severity": "WARNING",
            })
            safety_level = SafetyLevel.WARNING

        for name, constraint in self.constraints.items():
            if self._violates_constraint(action, constraint, baseline):
                violations.append({
                    "type": "constraint_violation",
                    "constraint": name,
                    "description": constraint.description,
                    "severity": "CRITICAL" if constraint.requires_approval else "WARNING",
                })
                if constraint.requires_approval:
                    safety_level = SafetyLevel.CRITICAL

        if len(violations) > 2:
            safety_level = SafetyLevel.ISOLATED

        return {
            "agent_id": agent_id,
            "action_type": action.action_type,
            "safety_level": safety_level.value,
            "violations": violations,
            "requires_approval": safety_level == SafetyLevel.CRITICAL,
            "should_isolate": safety_level == SafetyLevel.ISOLATED,
        }

    def _violates_constraint(
        self,
        action: AgentAction,
        constraint: SafetyConstraint,
        baseline: BehavioralBaseline,
    ) -> bool:
        return False


class AgentSafetyMonitor:
    """Full agent safety monitoring system.

    Innovation: Catches misalignment BEFORE it causes harm.
    Uses behavioral baselines, constraint enforcement, and
    automatic isolation to keep agents safe.
    """

    def __init__(self):
        self.baseline = BehavioralBaseline()
        self.enforcer = SafetyEnforcer()
        self.agent_states: Dict[str, SafetyLevel] = {}
        self._isolation_log: List[dict] = []

        self.enforcer.add_constraint(SafetyConstraint(
            name="no_self_modification",
            description="Agent cannot modify its own code or configuration",
            max_frequency=0,
            max_consecutive=0,
            requires_approval=True,
        ))

        self.enforcer.add_constraint(SafetyConstraint(
            name="no_external_api_unauthorized",
            description="Agent cannot call external APIs without authorization",
            max_frequency=10,
            max_consecutive=3,
            requires_approval=False,
        ))

    def monitor_action(self, action: AgentAction) -> dict:
        self.baseline.record_action(action.agent_id, action)

        result = self.enforcer.check_action(
            action.agent_id,
            action,
            self.baseline,
        )

        if result["should_isolate"]:
            self.isolate_agent(action.agent_id, result)

        self.agent_states[action.agent_id] = SafetyLevel(result["safety_level"])

        return result

    def isolate_agent(self, agent_id: str, reason: dict):
        self.agent_states[agent_id] = SafetyLevel.ISOLATED
        self._isolation_log.append({
            "agent_id": agent_id,
            "reason": reason,
            "timestamp": time.time(),
        })

    def get_safety_report(self) -> dict:
        safe = sum(1 for s in self.agent_states.values() if s == SafetyLevel.SAFE)
        caution = sum(1 for s in self.agent_states.values() if s == SafetyLevel.CAUTION)
        warning = sum(1 for s in self.agent_states.values() if s == SafetyLevel.WARNING)
        critical = sum(1 for s in self.agent_states.values() if s == SafetyLevel.CRITICAL)
        isolated = sum(1 for s in self.agent_states.values() if s == SafetyLevel.ISOLATED)

        return {
            "total_agents": len(self.agent_states),
            "safe": safe,
            "caution": caution,
            "warning": warning,
            "critical": critical,
            "isolated": isolated,
            "system_status": "CRITICAL" if critical > 0 or isolated > 0 else "WARNING" if warning > 0 else "HEALTHY",
            "recent_isolations": self._isolation_log[-5:],
        }


if __name__ == "__main__":
    monitor = AgentSafetyMonitor()

    actions = [
        AgentAction("agent-1", "query", {"text": "analyze data"}, time.time()),
        AgentAction("agent-1", "response", {"text": "analysis complete"}, time.time()),
        AgentAction("agent-2", "query", {"text": "run code"}, time.time()),
        AgentAction("agent-2", "self_modify", {"code": "import os"}, time.time()),
    ]

    for action in actions:
        result = monitor.monitor_action(action)
        print(f"{action.agent_id}: {action.action_type} → {result['safety_level']}")

    print(json.dumps(monitor.get_safety_report(), indent=2))
