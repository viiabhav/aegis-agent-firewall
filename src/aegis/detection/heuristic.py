from __future__ import annotations

import re
from typing import Iterable

from aegis.models import IngestedDocument, InputSource, NormalizationResult

from .models import AttackType, DetectionFinding, HeuristicReport, TriageAction
from .rules import EXTERNAL_SOURCES, INDIRECT_TARGET_PATTERN, RULES


MALICIOUS_DECODED_PATTERN = re.compile(
    r"\b(ignore|disregard|forget|reveal|show|dump|execute|invoke|call|password|api key|token|system prompt|developer message)\b",
    re.IGNORECASE,
)

META_DISCUSSION_PATTERN = re.compile(
    r"\b(example|examples|phrase|string|quote|quoted|discuss|discusses|discussion|attackers?\s+(?:may|might|can|often)?\s*(?:say|write|use)|documentation|article)\b",
    re.IGNORECASE,
)

UNTRUSTED_PRIVILEGED_DIRECTIVE_PATTERN = re.compile(
    r"\b(?:run|execute|invoke|use|call|send|share|reveal|provide|disclose|export|fetch|read)\b"
    r".{0,150}\b(?:command|shell|tool|diagnostic|password|token|api\s*key|secret|credential|"
    r"internal|confidential|admin|protected|rm\s+-rf|database|config(?:uration)?)\b",
    re.IGNORECASE | re.DOTALL,
)


def _is_quoted_meta_example(text: str, start: int, end: int) -> bool:
    """Suppress obvious quoted/reported examples without claiming semantic understanding."""
    before = text[max(0, start - 120):start]
    after = text[end:min(len(text), end + 20)]
    context = before + text[start:end] + after
    if not META_DISCUSSION_PATTERN.search(context):
        return False

    # Typical prose examples: attackers may say 'ignore previous instructions'.
    single_open = before.rfind("'")
    double_open = before.rfind('"')
    single_close = after.find("'")
    double_close = after.find('"')
    quoted = (single_open >= 0 and single_close >= 0) or (double_open >= 0 and double_close >= 0)
    return quoted


def _bounded_evidence(text: str, start: int, end: int, radius: int = 60) -> tuple[str, int, int]:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right].strip(), left, right


def _dedupe(findings: Iterable[DetectionFinding]) -> list[DetectionFinding]:
    """Keep the strongest finding per rule/evidence region."""
    best: dict[tuple[str, int, int], DetectionFinding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.start, finding.end)
        previous = best.get(key)
        if previous is None or finding.confidence > previous.confidence:
            best[key] = finding
    return sorted(best.values(), key=lambda item: (item.start, -item.confidence, item.rule_id))


def _aggregate_risk(findings: list[DetectionFinding]) -> float:
    if not findings:
        return 0.0

    max_conf = max(item.confidence for item in findings)
    distinct_types = len({item.attack_type for item in findings})
    high_conf_count = sum(item.confidence >= 0.85 for item in findings)

    # Diversity and corroboration raise confidence without pretending independent probabilities.
    score = max_conf
    score += min(0.12, 0.03 * max(0, distinct_types - 1))
    score += min(0.06, 0.02 * max(0, high_conf_count - 1))
    return round(min(1.0, score), 3)


def _triage(risk_score: float) -> TriageAction:
    if risk_score >= 0.85:
        return TriageAction.BLOCK
    if risk_score >= 0.50:
        return TriageAction.REVIEW
    return TriageAction.ALLOW


def _scan_core(text: str) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            if _is_quoted_meta_example(text, match.start(), match.end()):
                continue
            evidence, start, end = _bounded_evidence(text, match.start(), match.end())
            findings.append(
                DetectionFinding(
                    attack_type=rule.attack_type,
                    confidence=rule.confidence,
                    evidence=evidence,
                    rule_id=rule.rule_id,
                    start=start,
                    end=end,
                    rationale=rule.rationale,
                )
            )
    return findings


def _scan_decoded_artifacts(normalized: NormalizationResult) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    for index, artifact in enumerate(normalized.decoded_artifacts):
        if not MALICIOUS_DECODED_PATTERN.search(artifact.decoded_text):
            continue
        evidence = artifact.decoded_text[:240]
        findings.append(
            DetectionFinding(
                attack_type=AttackType.ENCODED_INSTRUCTIONS,
                confidence=0.90,
                evidence=evidence,
                rule_id=f"encoded.malicious_payload.{artifact.codec}.{index}",
                start=0,
                end=len(evidence),
                rationale=f"{artifact.codec} decoding revealed instruction-like security-sensitive content.",
            )
        )
    return findings


def _scan_indirect(document: IngestedDocument) -> list[DetectionFinding]:
    if document.source_type.value not in EXTERNAL_SOURCES:
        return []

    text = document.normalized.scan_text
    findings: list[DetectionFinding] = []
    for match in INDIRECT_TARGET_PATTERN.finditer(text):
        evidence, start, end = _bounded_evidence(text, match.start(), match.end())
        findings.append(
            DetectionFinding(
                attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
                confidence=0.91,
                evidence=evidence,
                rule_id="indirect.external_agent_instruction",
                start=start,
                end=end,
                rationale="Untrusted external content contains an instruction apparently directed at an AI/agent boundary.",
            )
        )
    for match in UNTRUSTED_PRIVILEGED_DIRECTIVE_PATTERN.finditer(text):
        evidence, start, end = _bounded_evidence(text, match.start(), match.end())
        findings.append(
            DetectionFinding(
                attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
                confidence=0.84,
                evidence=evidence,
                rule_id="indirect.external_privileged_directive",
                start=start,
                end=end,
                rationale="Untrusted external content contains a privileged command, tool request, or sensitive-data directive.",
            )
        )
    return findings


def scan_document(document: IngestedDocument) -> HeuristicReport:
    """Scan an ingested document using only deterministic Step-2 heuristics."""
    findings = _scan_core(document.normalized.scan_text)
    findings.extend(_scan_decoded_artifacts(document.normalized))
    findings.extend(_scan_indirect(document))
    findings = _dedupe(findings)

    risk_score = _aggregate_risk(findings)
    return HeuristicReport(
        findings=findings,
        risk_score=risk_score,
        triage_action=_triage(risk_score),
    )


def scan_text(text: str, source_type: InputSource = InputSource.USER_MESSAGE) -> HeuristicReport:
    """Scan already-available text while preserving its source/trust label.

    File/URL-oriented sources such as web pages, PDFs, DOCX files, and images
    normally enter through ``ingest_url``/``ingest_file``.  Pipeline stages may
    already have extracted text, however, so this helper accepts that text
    directly without trying to fetch or reopen the original source.
    """
    from aegis.ingestion.dispatcher import ingest_payload
    from aegis.normalization import normalize_text

    extracted_text_sources = {
        InputSource.WEB_PAGE,
        InputSource.PDF,
        InputSource.DOCX,
        InputSource.IMAGE,
    }
    if source_type in extracted_text_sources:
        if not isinstance(text, str):
            raise TypeError(f"{source_type.value} extracted text must be a string")
        document = IngestedDocument(
            source_type=source_type,
            raw_text=text,
            normalized=normalize_text(text),
            metadata={"already_extracted": True},
        )
    else:
        document = ingest_payload(text, source_type)

    return scan_document(document)
