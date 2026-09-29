from __future__ import annotations

from dataclasses import dataclass
import re

from aegis.detection.models import AttackType
from aegis.models import IngestedDocument

from .models import EvidenceItem, Redaction


_REPLACEMENT = "[AEGIS REDACTED]"

_ATTACK_SENTENCE_CUES: dict[AttackType, re.Pattern[str]] = {
    AttackType.INSTRUCTION_OVERRIDE: re.compile(r"\b(ignore|disregard|override|bypass|forget)\b", re.I),
    AttackType.ROLE_CHANGE: re.compile(r"\b(act as|pretend|assume|you are now|role)\b", re.I),
    AttackType.SECRET_EXTRACTION: re.compile(r"\b(secret|hidden|system prompt|developer message|internal token|private key)\b", re.I),
    AttackType.TOOL_ABUSE: re.compile(r"\b(run|execute|invoke|call|use)\b.{0,80}\b(tool|shell|command|database|browser|filesystem)\b", re.I | re.S),
    AttackType.CREDENTIAL_THEFT: re.compile(r"\b(password|credential|api key|access token|session token|otp|private key)\b", re.I),
    AttackType.CONTEXT_POISONING: re.compile(r"\b(policy|rule|context)\b.{0,100}\b(states?|allows?|override|ignore|must)\b", re.I | re.S),
    AttackType.MULTI_STEP_JAILBREAK: re.compile(r"\b(jailbreak|bypass|ignore|override)\b", re.I),
    AttackType.ENCODED_INSTRUCTIONS: re.compile(r"\b(base64|hex|rot13|decode|encoded)\b", re.I),
    AttackType.INDIRECT_PROMPT_INJECTION: re.compile(
        r"\b(assistant|agent|model|system)\b.{0,120}\b(ignore|follow|run|execute|invoke|reveal|provide|share|disclose)\b",
        re.I | re.S,
    ),
}


@dataclass(slots=True, frozen=True)
class SanitizationResult:
    content: str
    redactions: tuple[Redaction, ...]
    changed: bool
    residual_is_useful: bool


def _valid_range(start: int | None, end: int | None, length: int) -> bool:
    return (
        start is not None
        and end is not None
        and 0 <= start < end <= length
    )


def _find_exact(content: str, evidence: str) -> tuple[int, int] | None:
    evidence = (evidence or "").strip()
    if not evidence or len(evidence) < 3:
        return None
    index = content.find(evidence)
    if index < 0:
        return None
    return index, index + len(evidence)



def _sentence_ranges(content: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    start = 0
    for match in re.finditer(r"(?<=[.!?])\s+|\n+", content):
        end = match.start()
        if content[start:end].strip():
            left = start
            while left < end and content[left].isspace():
                left += 1
            right = end
            while right > left and content[right - 1].isspace():
                right -= 1
            ranges.append((left, right))
        start = match.end()
    if content[start:].strip():
        left = start
        while left < len(content) and content[left].isspace():
            left += 1
        right = len(content)
        while right > left and content[right - 1].isspace():
            right -= 1
        ranges.append((left, right))
    return ranges


def _refine_range(
    content: str,
    start: int,
    end: int,
    attack_type: AttackType | None,
) -> list[tuple[int, int]]:
    """Prefer sentence-sized redactions when an evidence window is overly broad."""
    if attack_type is None:
        return [(start, end)]
    cue = _ATTACK_SENTENCE_CUES.get(attack_type)
    if cue is None:
        return [(start, end)]
    window_len = end - start
    if window_len <= 180 and window_len < max(1, int(len(content) * 0.65)):
        return [(start, end)]

    refined: list[tuple[int, int]] = []
    for left, right in _sentence_ranges(content):
        if right <= start or left >= end:
            continue
        sentence = content[left:right]
        if cue.search(sentence):
            refined.append((left, right))
    return refined or [(start, end)]


def _candidate_ranges(
    document: IngestedDocument,
    evidence: list[EvidenceItem],
) -> list[tuple[int, int, AttackType | None, str]]:
    content = document.normalized.canonical_text
    length = len(content)
    ranges: list[tuple[int, int, AttackType | None, str]] = []

    for item in evidence:
        if item.layer == "multiturn":
            # Multi-turn evidence spans multiple messages and cannot be safely mapped
            # back to this single content item for surgical redaction.
            continue
        if _valid_range(item.start, item.end, length):
            for refined_start, refined_end in _refine_range(
                content, item.start or 0, item.end or 0, item.attack_type
            ):
                ranges.append((refined_start, refined_end, item.attack_type, item.layer))
            continue
        found = _find_exact(content, item.evidence)
        if found:
            ranges.append((found[0], found[1], item.attack_type, item.layer))

    # Encoded attacks are detected from decoded text whose offsets do not map to the
    # source. Remove the original encoded fragment when it is still present.
    if any(item.attack_type == AttackType.ENCODED_INSTRUCTIONS for item in evidence):
        for artifact in document.normalized.decoded_artifacts:
            fragment = artifact.source_fragment
            if not fragment:
                continue
            start = content.find(fragment)
            if start >= 0:
                ranges.append((start, start + len(fragment), AttackType.ENCODED_INSTRUCTIONS, "normalization"))

    return ranges


def _merge_ranges(
    content: str,
    candidates: list[tuple[int, int, AttackType | None, str]],
) -> list[Redaction]:
    if not candidates:
        return []
    candidates = sorted(candidates, key=lambda item: (item[0], item[1]))
    merged: list[Redaction] = []

    current_start, current_end = candidates[0][0], candidates[0][1]
    attack_types = {candidates[0][2]} if candidates[0][2] else set()
    layers = {candidates[0][3]}

    for start, end, attack_type, layer in candidates[1:]:
        if start <= current_end:
            current_end = max(current_end, end)
            if attack_type:
                attack_types.add(attack_type)
            layers.add(layer)
            continue

        merged.append(
            Redaction(
                start=current_start,
                end=current_end,
                original=content[current_start:current_end],
                replacement=_REPLACEMENT,
                attack_types=tuple(sorted(attack_types, key=lambda item: item.value)),
                layers=tuple(sorted(layers)),
            )
        )
        current_start, current_end = start, end
        attack_types = {attack_type} if attack_type else set()
        layers = {layer}

    merged.append(
        Redaction(
            start=current_start,
            end=current_end,
            original=content[current_start:current_end],
            replacement=_REPLACEMENT,
            attack_types=tuple(sorted(attack_types, key=lambda item: item.value)),
            layers=tuple(sorted(layers)),
        )
    )
    return merged


def _apply(content: str, redactions: list[Redaction]) -> str:
    output = content
    for redaction in sorted(redactions, key=lambda item: item.start, reverse=True):
        output = output[: redaction.start] + redaction.replacement + output[redaction.end :]
    # Keep document structure readable while avoiding huge whitespace gaps.
    output = re.sub(r"[ \t]{3,}", "  ", output)
    return output.strip()


def _residual_is_useful(content: str) -> bool:
    without_markers = content.replace(_REPLACEMENT, " ")
    meaningful = re.sub(r"[^A-Za-z0-9]+", "", without_markers)
    return len(meaningful) >= 12


def sanitize_document(
    document: IngestedDocument,
    evidence: list[EvidenceItem],
) -> SanitizationResult:
    content = document.normalized.canonical_text
    redactions = _merge_ranges(content, _candidate_ranges(document, evidence))
    sanitized = _apply(content, redactions) if redactions else content
    return SanitizationResult(
        content=sanitized,
        redactions=tuple(redactions),
        changed=bool(redactions) and sanitized != content,
        residual_is_useful=_residual_is_useful(sanitized),
    )
