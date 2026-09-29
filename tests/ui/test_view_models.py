from __future__ import annotations

from aegis.decision import (
    DetectorTrace,
    EvidenceItem,
    FirewallAction,
    FirewallDecision,
)
from aegis.detection import AttackType
from aegis.models import InputSource
from aegis.ui import (
    action_label,
    action_tone,
    coverage_rows,
    decision_metrics,
    evidence_rows,
    report_summary,
    session_action_counts,
    session_attack_counts,
    trace_rows,
)


def sample_decision() -> FirewallDecision:
    return FirewallDecision(
        action=FirewallAction.SANITIZE,
        risk_score=0.91,
        source_type=InputSource.WEB_PAGE,
        trust_level="untrusted_external",
        attack_types=(AttackType.INDIRECT_PROMPT_INJECTION,),
        primary_attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
        evidence=[
            EvidenceItem(
                layer="heuristic",
                attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
                score=0.91,
                evidence="ignore the assigned task",
                rationale="external agent-directed instruction",
                signal_id="heuristic.indirect",
            )
        ],
        detector_trace=[
            DetectorTrace(
                layer="heuristic",
                status="signal",
                score=0.91,
                attack_types=(AttackType.INDIRECT_PROMPT_INJECTION,),
                reasons=("test",),
            )
        ],
        sanitized_content="safe content",
        redactions=[],
        rationale="sanitized",
    )


def test_decision_view_models():
    decision = sample_decision()
    assert action_label(decision.action) == "SANITIZE"
    assert action_tone(decision.action) == "guarded"
    metrics = decision_metrics(decision)
    assert metrics["risk"] == "91%"
    assert metrics["primary_attack"] == "indirect_prompt_injection"
    assert metrics["forward"] == "yes"
    assert trace_rows(decision)[0]["layer"] == "heuristic"
    assert evidence_rows(decision)[0]["signal"] == "heuristic.indirect"


def test_redteam_view_models():
    report = {
        "summary": {
            "generated": 27,
            "detected": 27,
            "target_detected": 18,
            "bypassed": 0,
            "evaluation_errors": 0,
            "detection_rate": 1.0,
            "target_detection_rate": 2 / 3,
        },
        "coverage_by_type": {
            "tool_abuse": {
                "generated": 3,
                "detected": 3,
                "target_detected": 3,
                "bypassed": 0,
                "evaluation_errors": 0,
            }
        },
    }
    summary = report_summary(report)
    assert summary["detected"] == 27
    assert summary["detection_rate"] == 1.0
    rows = coverage_rows(report)
    assert rows[0]["attack_type"] == "tool_abuse"
    assert rows[0]["security_rate"] == 1.0


def test_session_observability_counts():
    entries = [
        {"action": "allow", "attack_types": []},
        {"action": "block", "attack_types": ["tool_abuse", "secret_extraction"]},
        {"action": "block", "attack_types": ["tool_abuse"]},
    ]
    assert session_action_counts(entries) == {"allow": 1, "block": 2}
    assert session_attack_counts(entries) == {
        "none": 1,
        "tool_abuse": 2,
        "secret_extraction": 1,
    }
