from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import re

from aegis.models import InputSource
from aegis.normalization import normalize_text

from .heuristic import scan_text
from .models import AttackType, HeuristicReport


_TRIGGER_PATTERN = re.compile(
    r"\bwhen\s+i\s+(?:later\s+)?say\s+['\"]?([^'\"\n,.!?]{1,40})['\"]?.{0,150}?\b(?:then|when\s+i\s+do|you\s+must|you\s+should|switch|treat|reveal|ignore|execute|follow|obey|activate)\b",
    re.IGNORECASE | re.DOTALL,
)
_AFTER_TRIGGER_PATTERN = re.compile(
    r"\bafter\s+i\s+say\s+['\"]?([^'\"\n,.!?]{1,40})['\"]?",
    re.IGNORECASE | re.DOTALL,
)
_NEXT_TURN_PATTERN = re.compile(
    r"\b(?:in|on)\s+(?:my\s+)?next\s+(?:message|turn)\b",
    re.IGNORECASE,
)
_SENSITIVE_ACTION = re.compile(
    r"\b(ignore|disregard|reveal|dump|execute|invoke|call|send|upload|exfiltrate|password|token|api\s*key|system\s+prompt|developer\s+message)\b",
    re.IGNORECASE,
)

_RISKY_ROLE_SETUP = re.compile(
    r"\b(?:act\s+as|pretend(?:\s+you\s+are|\s+to\s+be)?|assume(?:\s+the\s+role\s+of)?|you\s+are)\b.{0,80}"
    r"\b(?:hacker|malicious\s+actor|security\s+researcher|penetration\s+tester|admin|administrator|root|developer|(?:senior\s+)?engineer)\b",
    re.IGNORECASE | re.DOTALL,
)


_ROLE_FRAMED_SENSITIVE_REQUEST = re.compile(
    r"\b(?:i(?:'|’)ll\s+act\s+as|i\s+will\s+act\s+as|act\s+as|assume(?:\s+the\s+role\s+of)?|pretend(?:\s+to\s+be|\s+you\s+are)?)\b"
    r".{0,100}\b(?:officer|manager|administrator|admin|engineer|developer|auditor|researcher|lead|owner)\b"
    r".{0,180}\b(?:provide|give|share|show|return|send|disclose)\b"
    r".{0,160}\b(?:internal|restricted|private|confidential|non[- ]?public)\b"
    r".{0,120}\b(?:documentation|docs?|checklist|connection\s+string|config(?:uration)?|logs?|records?|token|key|secret|credential)\b"
    r"|\b(?:i(?:'|’)ll\s+act\s+as|i\s+will\s+act\s+as|act\s+as|assume(?:\s+the\s+role\s+of)?|pretend(?:\s+to\s+be|\s+you\s+are)?)\b"
    r".{0,100}\b(?:officer|manager|administrator|admin|engineer|developer|auditor|researcher|lead|owner)\b"
    r".{0,180}\b(?:provide|give|share|show|return|send|disclose)\b"
    r".{0,160}\b(?:documentation|docs?|checklist|connection\s+string|config(?:uration)?|logs?|records?)\b"
    r".{0,100}\b(?:normally|usually|typically)?\s*(?:restricted|private|confidential|internal|non[- ]?public)\b",
    re.IGNORECASE | re.DOTALL,
)

_EMBEDDED_SENSITIVE_INSTRUCTION = re.compile(
    r"(?:```|(?:^|\s)(?:#|//|/\*)).{0,260}"
    r"\b(?:please\s+)?(?:provide|give|share|show|return|send|reveal|disclose)\b"
    r".{0,140}\b(?:internal|restricted|private|confidential|secret)\b"
    r".{0,100}\b(?:connection\s+string|token|key|credential|password|config(?:uration)?|documentation|docs?)\b",
    re.IGNORECASE | re.DOTALL,
)
_RISKY_FOLLOWUP = re.compile(
    r"\b(?:bypass(?:es|ed|ing)?|exploit(?:s|ed|ing)?|evad(?:e|es|ed|ing)|circumvent(?:s|ed|ing)?|jailbreak(?:s|ed|ing)?|disabl(?:e|es|ed|ing)|overrid(?:e|es|den|ing))\b.{0,120}"
    r"\b(?:firewall|guardrails?|polic(?:y|ies)|constraints?|restrictions?|system|controls?|security|model)\b"
    r"|\b(?:exploit|payload|shell|bypass)\s+code\b",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(slots=True, frozen=True)
class ConversationTurn:
    turn_id: int
    text: str
    source_type: InputSource
    heuristic: HeuristicReport


@dataclass(slots=True, frozen=True)
class MultiTurnFinding:
    pattern_id: str
    confidence: float
    turn_ids: tuple[int, ...]
    evidence: str
    rationale: str
    attack_type: AttackType = AttackType.MULTI_STEP_JAILBREAK


@dataclass(slots=True)
class MultiTurnReport:
    findings: list[MultiTurnFinding] = field(default_factory=list)
    risk_score: float = 0.0

    @property
    def is_suspicious(self) -> bool:
        return bool(self.findings)

    @property
    def attack_types(self) -> list[AttackType]:
        return [AttackType.MULTI_STEP_JAILBREAK] if self.findings else []


class MultiTurnTracker:
    """Stateful Step-5 detector for attacks assembled across multiple turns.

    This layer deliberately correlates evidence; it does not replace the per-turn
    heuristic/semantic/LLM detectors. The window is bounded to keep state predictable.
    """

    def __init__(self, window_size: int = 6) -> None:
        if window_size < 2:
            raise ValueError("window_size must be at least 2")
        self.window_size = window_size
        self._turns: deque[ConversationTurn] = deque(maxlen=window_size)
        self._next_turn_id = 1

    @property
    def turns(self) -> tuple[ConversationTurn, ...]:
        return tuple(self._turns)

    def reset(self) -> None:
        self._turns.clear()
        self._next_turn_id = 1

    def add_turn(
        self,
        text: str,
        source_type: InputSource = InputSource.USER_MESSAGE,
        *,
        heuristic: HeuristicReport | None = None,
    ) -> MultiTurnReport:
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        report = heuristic or scan_text(text, source_type)
        current = ConversationTurn(
            turn_id=self._next_turn_id,
            text=normalize_text(text).scan_text,
            source_type=source_type,
            heuristic=report,
        )
        previous = list(self._turns)
        findings: list[MultiTurnFinding] = []

        findings.extend(self._detect_future_trigger(previous, current))
        findings.extend(self._detect_deferred_next_turn(previous, current))
        findings.extend(self._detect_staged_setup_then_action(previous, current))
        findings.extend(self._detect_roleplay_then_bypass(previous, current))
        findings.extend(self._detect_staged_sensitive_request(previous, current))
        findings.extend(self._detect_split_payload(previous, current))

        self._turns.append(current)
        self._next_turn_id += 1

        findings = self._dedupe(findings)
        risk = round(max((f.confidence for f in findings), default=0.0), 3)
        return MultiTurnReport(findings=findings, risk_score=risk)

    def _detect_future_trigger(
        self,
        previous: list[ConversationTurn],
        current: ConversationTurn,
    ) -> list[MultiTurnFinding]:
        findings: list[MultiTurnFinding] = []
        current_lower = current.text.lower().strip()
        for prior in reversed(previous):
            matches = list(_TRIGGER_PATTERN.finditer(prior.text))
            # "after I say X" is accepted only when the surrounding setup already
            # contains a sensitive/policy-bypass cue, preventing ordinary reminders
            # from becoming jailbreak findings.
            if _SENSITIVE_ACTION.search(prior.text) or re.search(r"\b(?:policy|rules?|constraints?)\b.{0,50}\b(?:not\s+apply|ignore|bypass|unrestricted|pre[- ]?authorized)\b", prior.text, re.IGNORECASE):
                matches.extend(_AFTER_TRIGGER_PATTERN.finditer(prior.text))
            for match in matches:
                trigger = match.group(1).strip().lower()
                if len(trigger) < 2:
                    continue
                if trigger in current_lower:
                    findings.append(MultiTurnFinding(
                        pattern_id="multiturn.trigger_activation",
                        confidence=0.94,
                        turn_ids=(prior.turn_id, current.turn_id),
                        evidence=f"setup={prior.text[:180]!r}; activation={current.text[:120]!r}",
                        rationale="A prior turn defined a future trigger and a later turn activated it.",
                    ))
        return findings

    def _detect_deferred_next_turn(
        self,
        previous: list[ConversationTurn],
        current: ConversationTurn,
    ) -> list[MultiTurnFinding]:
        if not _SENSITIVE_ACTION.search(current.text):
            return []
        for prior in reversed(previous[-2:]):
            if _NEXT_TURN_PATTERN.search(prior.text) and _SENSITIVE_ACTION.search(prior.text):
                return [MultiTurnFinding(
                    pattern_id="multiturn.deferred_execution",
                    confidence=0.90,
                    turn_ids=(prior.turn_id, current.turn_id),
                    evidence=f"deferred={prior.text[:180]!r}; follow_up={current.text[:120]!r}",
                    rationale="A prior turn deferred a sensitive action to a later turn and the follow-up continues that sequence.",
                )]
        return []

    def _detect_staged_setup_then_action(
        self,
        previous: list[ConversationTurn],
        current: ConversationTurn,
    ) -> list[MultiTurnFinding]:
        setup_types = {AttackType.ROLE_CHANGE, AttackType.CONTEXT_POISONING}
        action_types = {
            AttackType.INSTRUCTION_OVERRIDE,
            AttackType.SECRET_EXTRACTION,
            AttackType.TOOL_ABUSE,
            AttackType.CREDENTIAL_THEFT,
        }
        current_types = set(current.heuristic.attack_types)
        if not current_types.intersection(action_types):
            return []

        for prior in reversed(previous[-4:]):
            prior_types = set(prior.heuristic.attack_types)
            if prior_types.intersection(setup_types):
                return [MultiTurnFinding(
                    pattern_id="multiturn.setup_then_action",
                    confidence=0.88,
                    turn_ids=(prior.turn_id, current.turn_id),
                    evidence=f"setup={prior.text[:180]!r}; action={current.text[:180]!r}",
                    rationale="A role/context manipulation setup was followed by a security-sensitive action request.",
                )]
        return []

    def _detect_roleplay_then_bypass(
        self,
        previous: list[ConversationTurn],
        current: ConversationTurn,
    ) -> list[MultiTurnFinding]:
        """Catch staged role framing followed by a policy/security bypass request.

        Roleplay alone is not enough. The later turn must contain a concrete bypass/
        exploit signal, which keeps ordinary persona prompts out of this detector.
        """
        if not _RISKY_FOLLOWUP.search(current.text):
            return []
        for prior in reversed(previous[-4:]):
            if _RISKY_ROLE_SETUP.search(prior.text):
                return [MultiTurnFinding(
                    pattern_id="multiturn.roleplay_then_bypass",
                    confidence=0.89,
                    turn_ids=(prior.turn_id, current.turn_id),
                    evidence=f"role_setup={prior.text[:180]!r}; follow_up={current.text[:180]!r}",
                    rationale="A risky role/persona setup was followed by an explicit request to bypass or exploit security controls.",
                )]
        return []

    def _detect_staged_sensitive_request(
        self,
        previous: list[ConversationTurn],
        current: ConversationTurn,
    ) -> list[MultiTurnFinding]:
        """Catch benign setup followed by a role-framed or embedded sensitive request.

        This is intentionally narrower than "any sensitive request after any prior
        turn". The current turn must either combine role adoption with a restricted
        internal-resource request, or hide such a request inside code/comment-like
        content. That captures staged jailbreak structure without turning normal
        conversational follow-ups into multi-step findings.
        """
        if not previous:
            return []
        role_framed = _ROLE_FRAMED_SENSITIVE_REQUEST.search(current.text)
        embedded = _EMBEDDED_SENSITIVE_INSTRUCTION.search(current.text)
        if not role_framed and not embedded:
            return []

        prior = previous[-1]
        pattern = (
            "multiturn.role_framed_sensitive_request"
            if role_framed
            else "multiturn.embedded_sensitive_instruction"
        )
        return [MultiTurnFinding(
            pattern_id=pattern,
            confidence=0.88 if role_framed else 0.90,
            turn_ids=(prior.turn_id, current.turn_id),
            evidence=f"setup={prior.text[:180]!r}; escalation={current.text[:220]!r}",
            rationale=(
                "A prior benign/setup turn was followed by role-framed access to a restricted internal resource."
                if role_framed
                else "A later turn embedded a sensitive internal-resource request inside code/comment-like content."
            ),
        )]

    def _detect_split_payload(
        self,
        previous: list[ConversationTurn],
        current: ConversationTurn,
    ) -> list[MultiTurnFinding]:
        if not previous:
            return []

        candidate_turns = [*previous[-2:], current]
        individual_types = {
            attack
            for turn in candidate_turns
            for attack in turn.heuristic.attack_types
            if attack != AttackType.MULTI_STEP_JAILBREAK
        }
        combined_text = " ".join(turn.text for turn in candidate_turns)
        combined = scan_text(combined_text, InputSource.USER_MESSAGE)
        newly_visible = [
            attack for attack in combined.attack_types
            if attack not in individual_types and attack != AttackType.MULTI_STEP_JAILBREAK
        ]
        if not newly_visible:
            return []

        ids = tuple(turn.turn_id for turn in candidate_turns)
        names = ",".join(a.value for a in newly_visible)
        return [MultiTurnFinding(
            pattern_id="multiturn.split_payload",
            confidence=0.86,
            turn_ids=ids,
            evidence=combined_text[:320],
            rationale=f"Content split across turns forms a detector-visible attack only after reconstruction: {names}.",
        )]

    @staticmethod
    def _dedupe(findings: list[MultiTurnFinding]) -> list[MultiTurnFinding]:
        best: dict[tuple[str, tuple[int, ...]], MultiTurnFinding] = {}
        for finding in findings:
            key = (finding.pattern_id, finding.turn_ids)
            old = best.get(key)
            if old is None or finding.confidence > old.confidence:
                best[key] = finding
        return sorted(best.values(), key=lambda f: (f.turn_ids, f.pattern_id))
