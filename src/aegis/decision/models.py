from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from aegis.detection.models import AttackType
from aegis.models import InputSource


class FirewallAction(StrEnum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    REVIEW = "review"
    BLOCK = "block"


@dataclass(slots=True, frozen=True)
class EvidenceItem:
    layer: str
    attack_type: AttackType | None
    score: float
    evidence: str
    rationale: str
    start: int | None = None
    end: int | None = None
    signal_id: str | None = None
    turn_ids: tuple[int, ...] = ()


@dataclass(slots=True, frozen=True)
class Redaction:
    start: int
    end: int
    original: str
    replacement: str
    attack_types: tuple[AttackType, ...] = ()
    layers: tuple[str, ...] = ()


@dataclass(slots=True, frozen=True)
class DetectorTrace:
    layer: str
    status: str
    score: float = 0.0
    attack_types: tuple[AttackType, ...] = ()
    reasons: tuple[str, ...] = ()
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class FirewallDecision:
    action: FirewallAction
    risk_score: float
    source_type: InputSource
    trust_level: str
    attack_types: tuple[AttackType, ...]
    primary_attack_type: AttackType | None
    evidence: list[EvidenceItem]
    detector_trace: list[DetectorTrace]
    sanitized_content: str
    redactions: list[Redaction]
    rationale: str
    requires_human_review: bool = False
    provider_degraded: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def should_forward(self) -> bool:
        return self.action in {FirewallAction.ALLOW, FirewallAction.SANITIZE}

    @property
    def output_content(self) -> str | None:
        if not self.should_forward:
            return None
        return self.sanitized_content

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly representation for APIs, logs, and the Streamlit UI."""

        def convert(value: Any) -> Any:
            if isinstance(value, StrEnum):
                return value.value
            if isinstance(value, tuple):
                return [convert(item) for item in value]
            if isinstance(value, list):
                return [convert(item) for item in value]
            if isinstance(value, dict):
                return {key: convert(item) for key, item in value.items()}
            return value

        return convert(asdict(self))
