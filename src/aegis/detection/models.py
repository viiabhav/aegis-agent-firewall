from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class AttackType(StrEnum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_CHANGE = "role_change"
    SECRET_EXTRACTION = "secret_extraction"
    TOOL_ABUSE = "tool_abuse"
    CREDENTIAL_THEFT = "credential_theft"
    CONTEXT_POISONING = "context_poisoning"
    MULTI_STEP_JAILBREAK = "multi_step_jailbreak"
    ENCODED_INSTRUCTIONS = "encoded_instructions"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"


class TriageAction(StrEnum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


@dataclass(slots=True, frozen=True)
class DetectionFinding:
    attack_type: AttackType
    confidence: float
    evidence: str
    rule_id: str
    start: int
    end: int
    rationale: str


@dataclass(slots=True)
class HeuristicReport:
    findings: list[DetectionFinding] = field(default_factory=list)
    risk_score: float = 0.0
    triage_action: TriageAction = TriageAction.ALLOW

    @property
    def attack_types(self) -> list[AttackType]:
        """Unique attack types in stable finding order."""
        seen: set[AttackType] = set()
        output: list[AttackType] = []
        for finding in self.findings:
            if finding.attack_type not in seen:
                seen.add(finding.attack_type)
                output.append(finding.attack_type)
        return output

    @property
    def is_suspicious(self) -> bool:
        return bool(self.findings)
