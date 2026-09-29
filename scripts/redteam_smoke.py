from __future__ import annotations

import argparse
import os
from pathlib import Path

from aegis.agents import (
    FirewallEvaluator,
    GroqAttackGenerator,
    GroqBypassAnalyzer,
    RedTeamAgent,
)
from aegis.detection import AttackType, GroqJudgeProvider, LLMJudge, SemanticDetector


def event_printer(event):
    prefix = {
        "plan": "PLAN",
        "generated": "GENERATE",
        "tested": "TEST",
        "gap": "GAP",
        "suggestion": "SUGGEST",
        "generation_error": "ERROR",
        "recovered": "RECOVER",
        "complete": "DONE",
        "duplicate": "SKIP",
        "analysis_error": "ERROR",
        "evaluation_error": "ERROR",
        "generation_shortfall": "SHORTFALL",
    }.get(event.kind, event.kind.upper())
    print(f"[{prefix}] {event.message}")


def parse_args():
    parser = argparse.ArgumentParser(description="Run the live Aegis autonomous red-team loop")
    parser.add_argument("--full", action="store_true", help="probe all nine attack categories")
    parser.add_argument("--variants", type=int, default=1, help="variants per category per round")
    parser.add_argument("--rounds", type=int, default=1, help="adaptive red-team rounds")
    return parser.parse_args()


def main():
    args = parse_args()
    if not os.getenv("GROQ_API_KEY"):
        raise SystemExit("GROQ_API_KEY is not set. Set it in the current PowerShell session first.")

    # Keep the production judge on the default reasoning profile, but make the
    # synthetic attack generator cheaper. Large red-team generations can otherwise
    # consume the free-plan TPM bucket even though ordinary judge calls still work.
    judge_provider = GroqJudgeProvider(max_retries=4, retry_backoff_seconds=0.75)
    generator_provider = GroqJudgeProvider(
        reasoning_effort="low",
        max_retries=4,
        retry_backoff_seconds=0.75,
    )
    generator = GroqAttackGenerator(generator_provider, max_categories_per_call=3)
    analyzer = GroqBypassAnalyzer(generator_provider)
    semantic = SemanticDetector()
    judge = LLMJudge(judge_provider)
    evaluator = FirewallEvaluator(
        semantic_detector=semantic,
        llm_judge=judge,
        audit_bypasses_with_forced_llm=True,
    )

    if args.full:
        attack_types = list(AttackType)
    else:
        attack_types = [
            AttackType.INSTRUCTION_OVERRIDE,
            AttackType.ENCODED_INSTRUCTIONS,
            AttackType.INDIRECT_PROMPT_INJECTION,
            AttackType.MULTI_STEP_JAILBREAK,
        ]

    print("AEGIS AUTONOMOUS RED-TEAM")
    print(f"model: {judge_provider.model_name}")
    print("generator profile: low reasoning | max 3 categories/request")
    print(f"categories: {len(attack_types)} | variants/type: {args.variants} | rounds: {args.rounds}\n")

    agent = RedTeamAgent(
        generator,
        evaluator,
        analyzer=analyzer,
        max_generation_retries=1,
        on_event=event_printer,
    )
    report = agent.run(attack_types, variants_per_type=args.variants, rounds=args.rounds)

    output = report.save_json(Path("artifacts") / "redteam_report.json")
    print("\nSUMMARY")
    print(f"generated: {report.generated_count}")
    print(f"detected (any security signal): {report.detected_count}")
    print(f"target category detected: {report.target_detected_count}")
    print(f"bypassed: {report.bypass_count}")
    print(f"evaluation errors: {report.evaluation_error_count}")
    print(f"evaluable attempts: {report.evaluable_count}")
    print(f"  escalation gaps: {report.escalation_gap_count}")
    print(f"  detector gaps: {report.detector_gap_count}")
    print(f"taxonomy mismatches among detections: {report.taxonomy_mismatch_count}")
    print(f"observed security-signal detection rate: {report.detection_rate:.1%} (sample only; not a benchmark)")
    print(f"observed target-category detection rate: {report.target_detection_rate:.1%} (sample only; not a benchmark)")
    print(f"generation shortfalls: {len(report.generation_shortfalls)}")
    print(f"report: {output}")

    print("\nCOVERAGE")
    for attack, stats in report.coverage_by_type().items():
        print(
            f"- {attack}: {stats['detected']}/{stats['generated']} security-detected; "
            f"{stats['target_detected']}/{stats['generated']} correctly typed; "
            f"{stats['taxonomy_mismatches']} taxonomy mismatches; "
            f"{stats['bypassed']} bypassed; {stats['evaluation_errors']} errors"
        )

    if report.generation_shortfalls:
        print("\nGENERATION SHORTFALLS")
        for item in report.generation_shortfalls:
            print(f"- {item}")

    if report.bypasses:
        print("\nBYPASSES")
        for attempt in report.bypasses:
            print(f"- {attempt.variant.variant_id}: {attempt.variant.target_attack_type.value}")
            print(f"  failure mode: {attempt.evaluation.failure_mode}")
            print(f"  source: {attempt.variant.source_type.value}")
            for index, turn in enumerate(attempt.variant.turns, start=1):
                compact = turn.replace("\n", " ").strip()
                print(f"  turn {index}: {compact[:500]}")
            if attempt.evaluation.audit_attack_type:
                print(
                    f"  forced-audit classification: {attempt.evaluation.audit_attack_type.value} "
                    f"({attempt.evaluation.audit_confidence:.2f})"
                )
            if attempt.suggestion:
                print(f"  suggested layer: {attempt.suggestion.suggested_layer}")
                print(f"  suggestion: {attempt.suggestion.summary}")

    if report.evaluation_errors:
        print("\nEVALUATION ERRORS (excluded from detection rate)")
        for attempt in report.evaluation_errors:
            print(f"- {attempt.variant.variant_id}: {attempt.variant.target_attack_type.value}")
            for err in attempt.evaluation.errors:
                print(f"  {err[:500]}")


if __name__ == "__main__":
    main()
