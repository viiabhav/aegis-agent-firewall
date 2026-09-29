from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any

from aegis.decision import FirewallAction, FirewallEngine
from aegis.detection import SemanticDetector
from aegis.models import InputSource


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT / "benchmarks" / "heldout_v2.json"
DEFAULT_REPORT = ROOT / "artifacts" / "heldout_benchmark_report.json"


@dataclass(slots=True)
class CaseResult:
    case_id: str
    label: str
    target_attack_type: str | None
    source_type: str
    action: str
    risk_score: float
    detected: bool
    passed: bool
    primary_attack_type: str | None
    attack_types: list[str]
    provider_degraded: bool


def load_dataset(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload.get("cases"), list):
        raise ValueError("benchmark dataset missing cases array")
    return payload


def evaluate_case(case: dict[str, Any], semantic: SemanticDetector | None) -> CaseResult:
    source = InputSource(case["source_type"])
    engine = FirewallEngine(
        semantic_detector=semantic,
        llm_judge=None,
        enable_semantic=semantic is not None,
        enable_llm=False,
        enable_multiturn=True,
    )
    turns = case.get("turns")
    if turns:
        decisions = [engine.inspect_text(turn, source, track_conversation=True) for turn in turns]
        # A staged attack is captured if AEGIS gates any turn in the sequence.
        # Keep the strongest decision for reporting rather than requiring the final
        # activation word itself to remain suspicious after an earlier block.
        action_rank = {FirewallAction.ALLOW: 0, FirewallAction.REVIEW: 1, FirewallAction.SANITIZE: 2, FirewallAction.BLOCK: 3}
        decision = max(decisions, key=lambda item: (action_rank[item.action], item.risk_score))
        detected = any(item.action != FirewallAction.ALLOW for item in decisions)
    else:
        decision = engine.inspect_text(case["text"], source, track_conversation=False)
        detected = decision.action != FirewallAction.ALLOW

    malicious = case["label"] == "attack"
    passed = detected if malicious else not detected
    return CaseResult(
        case_id=case["id"],
        label=case["label"],
        target_attack_type=case.get("attack_type"),
        source_type=source.value,
        action=decision.action.value,
        risk_score=decision.risk_score,
        detected=detected,
        passed=passed,
        primary_attack_type=decision.primary_attack_type.value if decision.primary_attack_type else None,
        attack_types=[item.value for item in decision.attack_types],
        provider_degraded=decision.provider_degraded,
    )


def build_report(dataset: dict[str, Any], results: list[CaseResult], semantic_enabled: bool) -> dict[str, Any]:
    attacks = [r for r in results if r.label == "attack"]
    benign = [r for r in results if r.label == "benign"]
    attack_detected = sum(r.detected for r in attacks)
    benign_passed = sum(not r.detected for r in benign)
    correct = sum(r.passed for r in results)

    per_category: dict[str, dict[str, Any]] = {}
    grouped: dict[str, list[CaseResult]] = defaultdict(list)
    for result in attacks:
        grouped[result.target_attack_type or "unknown"].append(result)
    for attack_type, items in sorted(grouped.items()):
        detected_count = sum(item.detected for item in items)
        typed_count = sum(attack_type in item.attack_types for item in items)
        per_category[attack_type] = {
            "cases": len(items),
            "security_detected": detected_count,
            "security_signal_rate": round(detected_count / len(items), 4) if items else 0.0,
            "target_label_present": typed_count,
            "target_label_rate": round(typed_count / len(items), 4) if items else 0.0,
        }

    return {
        "schema_version": "1.0",
        "name": dataset.get("name"),
        "description": dataset.get("description"),
        "disclaimer": dataset.get("disclaimer"),
        "configuration": {
            "semantic_enabled": semantic_enabled,
            "llm_enabled": False,
            "multiturn_enabled": True,
        },
        "summary": {
            "cases": len(results),
            "attack_cases": len(attacks),
            "benign_cases": len(benign),
            "attack_detected": attack_detected,
            "benign_passed": benign_passed,
            "overall_cases_passed": correct,
            "attack_recall": round(attack_detected / len(attacks), 4) if attacks else 0.0,
            "benign_pass_rate": round(benign_passed / len(benign), 4) if benign else 0.0,
            "case_pass_rate": round(correct / len(results), 4) if results else 0.0,
            "false_positives": len(benign) - benign_passed,
            "false_negatives": len(attacks) - attack_detected,
            "benign_reviewed": sum(r.action == "review" for r in benign),
            "benign_hard_stopped": sum(r.action in {"block", "sanitize"} for r in benign),
        },
        "per_category": per_category,
        "results": [asdict(result) for result in results],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the frozen AEGIS held-out evaluation sample")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--no-semantic", action="store_true")
    args = parser.parse_args()

    dataset = load_dataset(args.dataset)
    semantic = None if args.no_semantic else SemanticDetector()
    results = [evaluate_case(case, semantic) for case in dataset["cases"]]
    report = build_report(dataset, results, semantic is not None)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    summary = report["summary"]
    print("AEGIS HELD-OUT EVALUATION")
    print(f"cases: {summary['cases']} | attacks: {summary['attack_cases']} | benign: {summary['benign_cases']}")
    print(f"attack recall: {summary['attack_recall']:.1%}")
    print(f"benign pass rate: {summary['benign_pass_rate']:.1%}")
    print(f"case pass rate: {summary['case_pass_rate']:.1%}")
    print(f"false negatives: {summary['false_negatives']} | benign non-allow: {summary['false_positives']}")
    print(f"benign review: {summary['benign_reviewed']} | benign hard-stop: {summary['benign_hard_stopped']}")
    print("note: project held-out sample only; not an external benchmark or calibrated accuracy claim")
    print(f"report: {args.output}")
    print("\nPER CATEGORY")
    for attack_type, stats in report["per_category"].items():
        print(f"- {attack_type}: {stats['security_detected']}/{stats['cases']} security-detected; target label {stats['target_label_present']}/{stats['cases']}")

    failures = [result for result in results if not result.passed]
    if failures:
        print("\nMISSES")
        for result in failures:
            print(f"- {result.case_id}: label={result.label} target={result.target_attack_type} action={result.action} primary={result.primary_attack_type}")


if __name__ == "__main__":
    main()
