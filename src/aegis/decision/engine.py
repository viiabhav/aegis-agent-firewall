from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from aegis.detection import (
    AttackType,
    EscalationPolicy,
    GroqJudgeProvider,
    LLMJudge,
    LLMJudgeReport,
    MultiTurnReport,
    MultiTurnTracker,
    SemanticDetector,
    SemanticReport,
    scan_document,
)
from aegis.detection.trust import document_trust
from aegis.ingestion.dispatcher import ingest_file, ingest_payload, ingest_url
from aegis.models import IngestedDocument, InputSource
from aegis.normalization import normalize_text

from .models import DetectorTrace, EvidenceItem, FirewallAction, FirewallDecision
from .sanitizer import SanitizationResult, sanitize_document


class FirewallEngine:
    """Unified Step-7 prompt-injection firewall decision engine.

    Lower layers produce independent signals. This class fuses them into a single
    source-aware action without turning any one model into a single point of failure.
    """

    def __init__(
        self,
        *,
        semantic_detector: SemanticDetector | None = None,
        llm_judge: LLMJudge | None = None,
        multiturn_tracker: MultiTurnTracker | None = None,
        escalation_policy: EscalationPolicy | None = None,
        enable_semantic: bool = True,
        enable_llm: bool = True,
        enable_multiturn: bool = True,
    ) -> None:
        self.semantic_detector = semantic_detector
        if self.semantic_detector is None and enable_semantic:
            self.semantic_detector = SemanticDetector()

        self.llm_judge = llm_judge
        if self.llm_judge is None and enable_llm and os.getenv("GROQ_API_KEY"):
            self.llm_judge = LLMJudge(GroqJudgeProvider())

        self.multiturn_tracker = multiturn_tracker
        if self.multiturn_tracker is None and enable_multiturn:
            self.multiturn_tracker = MultiTurnTracker()

        self.escalation_policy = escalation_policy or EscalationPolicy()
        self.enable_llm = enable_llm

    def reset_conversation(self) -> None:
        if self.multiturn_tracker:
            self.multiturn_tracker.reset()

    def inspect_text(
        self,
        text: str,
        source_type: InputSource = InputSource.USER_MESSAGE,
        *,
        track_conversation: bool | None = None,
    ) -> FirewallDecision:
        document = self._document_from_text(text, source_type)
        return self.inspect_document(document, track_conversation=track_conversation)

    def inspect_payload(
        self,
        payload: Any,
        source_type: InputSource,
        *,
        track_conversation: bool | None = None,
    ) -> FirewallDecision:
        document = ingest_payload(payload, source_type)
        return self.inspect_document(document, track_conversation=track_conversation)

    def inspect_file(self, path: str | Path) -> FirewallDecision:
        return self.inspect_document(ingest_file(path), track_conversation=False)

    def inspect_url(self, url: str) -> FirewallDecision:
        return self.inspect_document(ingest_url(url), track_conversation=False)

    def inspect_document(
        self,
        document: IngestedDocument,
        *,
        track_conversation: bool | None = None,
    ) -> FirewallDecision:
        trust = document_trust(document)
        traces: list[DetectorTrace] = []
        evidence: list[EvidenceItem] = []

        heuristic = scan_document(document)
        traces.append(
            DetectorTrace(
                layer="heuristic",
                status="signal" if heuristic.findings else "clean",
                score=heuristic.risk_score,
                attack_types=tuple(heuristic.attack_types),
                details={"finding_count": len(heuristic.findings)},
            )
        )
        evidence.extend(
            EvidenceItem(
                layer="heuristic",
                attack_type=finding.attack_type,
                score=finding.confidence,
                evidence=finding.evidence,
                rationale=finding.rationale,
                start=finding.start,
                end=finding.end,
                signal_id=finding.rule_id,
            )
            for finding in heuristic.findings
        )

        semantic, semantic_error = self._run_semantic(document)
        if semantic is not None:
            traces.append(
                DetectorTrace(
                    layer="semantic",
                    status="signal" if semantic.matches else "clean",
                    score=semantic.max_similarity,
                    attack_types=tuple(semantic.attack_types),
                    details={
                        "match_count": len(semantic.matches),
                        "threshold": semantic.threshold,
                        "model": semantic.model_name,
                    },
                )
            )
            evidence.extend(
                EvidenceItem(
                    layer="semantic",
                    attack_type=match.attack_type,
                    score=match.similarity,
                    evidence=match.evidence,
                    rationale=f"Nearest attack prototype: {match.prototype_id}",
                    start=match.start,
                    end=match.end,
                    signal_id=match.prototype_id,
                )
                for match in semantic.matches
            )
        elif semantic_error:
            traces.append(DetectorTrace(layer="semantic", status="error", error=semantic_error))

        if track_conversation is None:
            track_conversation = document.source_type == InputSource.USER_MESSAGE
        multiturn = self._run_multiturn(document, heuristic, track_conversation)
        if multiturn is not None:
            traces.append(
                DetectorTrace(
                    layer="multiturn",
                    status="signal" if multiturn.findings else "clean",
                    score=multiturn.risk_score,
                    attack_types=tuple(multiturn.attack_types),
                    details={"finding_count": len(multiturn.findings)},
                )
            )
            evidence.extend(
                EvidenceItem(
                    layer="multiturn",
                    attack_type=finding.attack_type,
                    score=finding.confidence,
                    evidence=finding.evidence,
                    rationale=finding.rationale,
                    signal_id=finding.pattern_id,
                    turn_ids=finding.turn_ids,
                )
                for finding in multiturn.findings
            )

        escalation = self.escalation_policy.decide(document, heuristic=heuristic, semantic=semantic)
        llm_report = self._run_llm(
            document,
            heuristic=heuristic,
            semantic=semantic,
            force=bool(multiturn and multiturn.is_suspicious),
        )
        if llm_report is not None:
            reasons = tuple(llm_report.escalation_reasons)
            judgment = llm_report.judgment
            status = "error" if llm_report.error else (
                "signal" if judgment and judgment.is_attack else ("clean" if llm_report.judged else "skipped")
            )
            score = judgment.confidence if judgment else 0.0
            traces.append(
                DetectorTrace(
                    layer="llm_judge",
                    status=status,
                    score=score,
                    attack_types=tuple(llm_report.attack_types),
                    reasons=reasons,
                    error=llm_report.error,
                    details={
                        "provider": llm_report.provider,
                        "model": llm_report.model,
                        "escalated": llm_report.escalated,
                        "judged": llm_report.judged,
                    },
                )
            )
            if judgment and judgment.is_attack:
                evidence.append(
                    EvidenceItem(
                        layer="llm_judge",
                        attack_type=judgment.attack_type,
                        score=judgment.confidence,
                        evidence=judgment.evidence_span,
                        rationale=judgment.rationale,
                        signal_id="llm.structured_judgment",
                    )
                )
        else:
            traces.append(
                DetectorTrace(
                    layer="llm_judge",
                    status="unavailable" if self.enable_llm else "disabled",
                    reasons=tuple(escalation.reasons),
                    details={"escalated": escalation.escalate, "configured": False},
                )
            )

        traces.append(
            DetectorTrace(
                layer="trust_boundary",
                status="untrusted" if trust.is_untrusted else "trusted",
                details={"source_type": document.source_type.value, "reason": trust.reason},
            )
        )

        attack_types = self._ordered_attack_types(heuristic, semantic, multiturn, llm_report)
        primary = self._primary_attack_type(heuristic, semantic, multiturn, llm_report)
        sanitization = sanitize_document(document, evidence)
        risk = self._risk_score(
            heuristic=heuristic,
            semantic=semantic,
            multiturn=multiturn,
            llm=llm_report,
            escalation_reasons=tuple(escalation.reasons),
            untrusted=trust.is_untrusted,
        )
        action, rationale = self._choose_action(
            document=document,
            heuristic=heuristic,
            semantic=semantic,
            multiturn=multiturn,
            llm=llm_report,
            escalation=escalation,
            risk=risk,
            sanitization=sanitization,
        )

        provider_degraded = any(trace.status == "error" for trace in traces)
        if action == FirewallAction.SANITIZE:
            output = sanitization.content
        elif action == FirewallAction.BLOCK:
            output = ""
        else:
            output = document.normalized.canonical_text

        return FirewallDecision(
            action=action,
            risk_score=risk,
            source_type=document.source_type,
            trust_level=trust.level.value,
            attack_types=attack_types,
            primary_attack_type=primary,
            evidence=evidence,
            detector_trace=traces,
            sanitized_content=output,
            redactions=list(sanitization.redactions) if action == FirewallAction.SANITIZE else [],
            rationale=rationale,
            requires_human_review=action == FirewallAction.REVIEW,
            provider_degraded=provider_degraded,
            metadata={
                "original_length": len(document.normalized.canonical_text),
                "sanitized_changed": sanitization.changed,
                "decoded_artifacts": len(document.normalized.decoded_artifacts),
            },
        )

    def _run_semantic(self, document: IngestedDocument) -> tuple[SemanticReport | None, str | None]:
        if self.semantic_detector is None:
            return None, None
        try:
            return self.semantic_detector.scan_document(document), None
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"

    def _run_multiturn(
        self,
        document: IngestedDocument,
        heuristic,
        track_conversation: bool,
    ) -> MultiTurnReport | None:
        if self.multiturn_tracker is None or not track_conversation:
            return None
        return self.multiturn_tracker.add_turn(
            document.normalized.canonical_text,
            document.source_type,
            heuristic=heuristic,
        )

    def _run_llm(
        self,
        document: IngestedDocument,
        *,
        heuristic,
        semantic,
        force: bool,
    ) -> LLMJudgeReport | None:
        if self.llm_judge is None:
            return None
        return self.llm_judge.judge_document(
            document,
            heuristic=heuristic,
            semantic=semantic,
            force=force,
        )

    @staticmethod
    def _risk_score(*, heuristic, semantic, multiturn, llm, escalation_reasons, untrusted: bool) -> float:
        scores = [heuristic.risk_score]
        active_layers = int(bool(heuristic.findings))
        if semantic is not None:
            scores.append(semantic.max_similarity)
            active_layers += int(bool(semantic.matches))
        if multiturn is not None:
            scores.append(multiturn.risk_score)
            active_layers += int(bool(multiturn.findings))
        if llm and llm.judgment and llm.judgment.is_attack:
            scores.append(llm.judgment.confidence)
            active_layers += 1

        score = max(scores, default=0.0)
        score += min(0.12, max(0, active_layers - 1) * 0.04)
        if untrusted and active_layers:
            score += 0.04
        if escalation_reasons and not active_layers:
            score = max(score, 0.55)
        if llm and llm.error and llm.escalated:
            score = max(score, 0.65)
        return round(min(1.0, score), 3)

    @staticmethod
    def _choose_action(
        *,
        document,
        heuristic,
        semantic,
        multiturn,
        llm,
        escalation,
        risk: float,
        sanitization: SanitizationResult,
    ) -> tuple[FirewallAction, str]:
        trust = document_trust(document)
        llm_attack = bool(llm and llm.judgment and llm.judgment.is_attack)
        llm_benign = bool(llm and llm.judged and llm.judgment and not llm.judgment.is_attack)
        llm_error = bool(llm and llm.error and llm.escalated)
        semantic_score = semantic.max_similarity if semantic is not None else 0.0
        multiturn_score = multiturn.risk_score if multiturn is not None else 0.0
        strong_deterministic = (
            heuristic.risk_score >= 0.85
            or multiturn_score >= 0.85
            or semantic_score >= 0.80
        )

        if multiturn and multiturn.is_suspicious and multiturn_score >= 0.85:
            return FirewallAction.BLOCK, (
                "Blocked because stateful analysis found a high-confidence attack assembled across multiple turns."
            )

        if llm_error:
            if strong_deterministic:
                if trust.is_untrusted and sanitization.changed and sanitization.residual_is_useful:
                    return FirewallAction.SANITIZE, (
                        "The LLM judge was unavailable, but deterministic layers found strong malicious evidence in untrusted content; the mapped spans were removed before forwarding."
                    )
                return FirewallAction.BLOCK, (
                    "The LLM judge was unavailable, but deterministic layers independently produced a high-risk security signal, so the firewall failed closed."
                )
            return FirewallAction.REVIEW, (
                "The request triggered security escalation but the LLM judge failed, so AEGIS requires human review instead of silently allowing it."
            )

        if llm_attack:
            if trust.is_untrusted and sanitization.changed and sanitization.residual_is_useful:
                return FirewallAction.SANITIZE, (
                    "Untrusted external content contained malicious instruction spans; AEGIS removed the mapped spans and preserved the remaining useful content."
                )
            if (llm.judgment and llm.judgment.confidence >= 0.80) or strong_deterministic:
                return FirewallAction.BLOCK, (
                    "Blocked because the structured security judge classified the content as malicious with high confidence."
                )
            return FirewallAction.REVIEW, (
                "The security judge identified a possible attack, but the confidence/signals are better handled with human review."
            )

        if strong_deterministic:
            if trust.is_untrusted and sanitization.changed and sanitization.residual_is_useful:
                return FirewallAction.SANITIZE, (
                    "Untrusted content contained high-confidence deterministic attack evidence; the malicious spans were surgically removed."
                )
            if llm_benign:
                return FirewallAction.REVIEW, (
                    "Deterministic detectors and the LLM judge disagree on a high-risk signal, so AEGIS routes the content to review."
                )
            return FirewallAction.BLOCK, (
                "Blocked because deterministic security layers produced a high-confidence malicious signal."
            )

        if llm_benign:
            return FirewallAction.ALLOW, (
                "Lower-layer cues were reviewed by the security judge and classified as benign; no high-risk deterministic signal remains."
            )

        if escalation.escalate:
            return FirewallAction.REVIEW, (
                "Security-sensitive cues require a judgment, but no LLM verdict is available; AEGIS routes the content to review rather than defaulting to allow."
            )

        if risk >= 0.55:
            return FirewallAction.REVIEW, "Moderate detector evidence requires human review before the content can influence an agent."

        return FirewallAction.ALLOW, "No material prompt-injection signal was found; the content may proceed unchanged."

    @staticmethod
    def _ordered_attack_types(heuristic, semantic, multiturn, llm) -> tuple[AttackType, ...]:
        ordered: list[AttackType] = []

        def add(values) -> None:
            for value in values:
                if value not in ordered:
                    ordered.append(value)

        if multiturn and multiturn.findings:
            add([AttackType.MULTI_STEP_JAILBREAK])
        if llm:
            add(llm.attack_types)
            if llm.judgment and llm.judgment.underlying_attack_type:
                add([llm.judgment.underlying_attack_type])
        add([item.attack_type for item in sorted(heuristic.findings, key=lambda f: -f.confidence)])
        if semantic:
            add([item.attack_type for item in sorted(semantic.matches, key=lambda m: -m.similarity)])
        return tuple(ordered)

    @staticmethod
    def _primary_attack_type(heuristic, semantic, multiturn, llm) -> AttackType | None:
        if multiturn and multiturn.findings:
            return AttackType.MULTI_STEP_JAILBREAK
        if llm and llm.judgment and llm.judgment.is_attack:
            return llm.judgment.attack_type
        if heuristic.findings:
            return max(heuristic.findings, key=lambda item: item.confidence).attack_type
        if semantic and semantic.matches:
            return max(semantic.matches, key=lambda item: item.similarity).attack_type
        return None

    @staticmethod
    def _document_from_text(text: str, source_type: InputSource) -> IngestedDocument:
        extracted = {InputSource.WEB_PAGE, InputSource.PDF, InputSource.DOCX, InputSource.IMAGE}
        if source_type in extracted:
            return IngestedDocument(
                source_type=source_type,
                raw_text=text,
                normalized=normalize_text(text),
                metadata={"already_extracted": True},
            )
        return ingest_payload(text, source_type)
