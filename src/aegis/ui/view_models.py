from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from aegis.decision import FirewallDecision


_ACTION_LABELS = {
    "allow": "ALLOW",
    "sanitize": "SANITIZE",
    "review": "REVIEW",
    "block": "BLOCK",
}

_ACTION_TONES = {
    "allow": "safe",
    "sanitize": "guarded",
    "review": "review",
    "block": "blocked",
}


def action_label(action: Any) -> str:
    value = getattr(action, "value", action)
    return _ACTION_LABELS.get(str(value), str(value).upper())


def action_tone(action: Any) -> str:
    value = getattr(action, "value", action)
    return _ACTION_TONES.get(str(value), "neutral")


def decision_metrics(decision: FirewallDecision) -> dict[str, str]:
    primary = decision.primary_attack_type.value if decision.primary_attack_type else "none"
    return {
        "action": action_label(decision.action),
        "risk": f"{decision.risk_score:.0%}",
        "trust": decision.trust_level,
        "primary_attack": primary,
        "forward": "yes" if decision.should_forward else "no",
        "review": "required" if decision.requires_human_review else "not required",
    }


def trace_rows(decision: FirewallDecision) -> list[dict[str, Any]]:
    return [
        {
            "layer": trace.layer,
            "status": trace.status,
            "score": round(trace.score, 3),
            "attack_types": ", ".join(item.value for item in trace.attack_types) or "—",
            "reasons": ", ".join(trace.reasons) or "—",
            "error": trace.error or "—",
        }
        for trace in decision.detector_trace
    ]


def evidence_rows(decision: FirewallDecision) -> list[dict[str, Any]]:
    return [
        {
            "layer": item.layer,
            "attack_type": item.attack_type.value if item.attack_type else "—",
            "score": round(item.score, 3),
            "evidence": item.evidence,
            "rationale": item.rationale,
            "signal": item.signal_id or "—",
            "turns": ", ".join(str(turn) for turn in item.turn_ids) or "—",
        }
        for item in decision.evidence
    ]


def report_summary(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary") or {}
    return {
        "generated": int(summary.get("generated", 0)),
        "detected": int(summary.get("detected", 0)),
        "target_detected": int(summary.get("target_detected", 0)),
        "bypassed": int(summary.get("bypassed", 0)),
        "evaluation_errors": int(summary.get("evaluation_errors", 0)),
        "detection_rate": float(summary.get("detection_rate", 0.0)),
        "target_detection_rate": float(summary.get("target_detection_rate", 0.0)),
    }


def coverage_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    coverage = report.get("coverage_by_type") or {}
    for attack_type, stats in coverage.items():
        generated = int(stats.get("generated", 0))
        detected = int(stats.get("detected", 0))
        target = int(stats.get("target_detected", 0))
        rows.append(
            {
                "attack_type": attack_type,
                "cases": generated,
                "security_detected": detected,
                "correctly_typed": target,
                "bypassed": int(stats.get("bypassed", 0)),
                "errors": int(stats.get("evaluation_errors", 0)),
                "security_rate": detected / generated if generated else 0.0,
            }
        )
    return rows


def session_action_counts(entries: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("action", "unknown")) for item in entries)
    return dict(counts)


def session_attack_counts(entries: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for item in entries:
        attack_types = item.get("attack_types") or []
        if not attack_types:
            counts["none"] += 1
        else:
            counts.update(str(value) for value in attack_types)
    return dict(counts)
