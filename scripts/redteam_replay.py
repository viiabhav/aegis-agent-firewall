from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from aegis.agents import FirewallEvaluator, ReplayCorpus, run_replay
from aegis.detection import SemanticDetector


def parse_args():
    parser = argparse.ArgumentParser(
        description="Replay the persisted AEGIS red-team regression corpus without an LLM provider"
    )
    parser.add_argument(
        "--corpus",
        default="artifacts/redteam_attack_corpus.json",
        help="path to persisted replay corpus",
    )
    parser.add_argument(
        "--output",
        default="artifacts/redteam_replay_report.json",
        help="path for the deterministic replay report",
    )
    parser.add_argument(
        "--no-semantic",
        action="store_true",
        help="skip local semantic embeddings (heuristic + escalation + multi-turn only)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    corpus = ReplayCorpus.load(args.corpus)
    semantic = None if args.no_semantic else SemanticDetector()
    evaluator = FirewallEvaluator(
        semantic_detector=semantic,
        llm_judge=None,
        audit_bypasses_with_forced_llm=False,
        count_escalation_without_llm=True,
    )
    result = run_replay(corpus, evaluator)
    report = result.report
    output = result.save_json(Path(args.output))

    counts = Counter(case.target_attack_type.value for case in corpus.cases)
    print("AEGIS RED-TEAM REPLAY")
    print("mode: deterministic regression replay")
    print("provider generation required: NO")
    print("LLM judge required: NO")
    print(f"local semantic layer: {'OFF' if args.no_semantic else 'ON'}")
    print(f"corpus: {len(corpus.cases)} cases | categories: {len(corpus.categories)}/{len(counts)}")
    print(f"origin: {corpus.origin}")
    print(f"disclaimer: {corpus.disclaimer}\n")

    print("CORPUS")
    for attack_type in corpus.categories:
        print(f"- {attack_type.value}: {counts[attack_type.value]} cases")

    print("\nSUMMARY")
    print(f"replayed: {report.generated_count}")
    print(f"detected (any security signal): {report.detected_count}")
    print(f"target category identified by available offline detectors: {report.target_detected_count}")
    print(f"bypassed: {report.bypass_count}")
    print(f"evaluation errors: {report.evaluation_error_count}")
    print(f"  escalation gaps: {report.escalation_gap_count}")
    print(f"  detector gaps: {report.detector_gap_count}")
    print(f"taxonomy mismatches among detections: {report.taxonomy_mismatch_count}")
    print(f"observed security-signal replay rate: {report.detection_rate:.1%} (regression corpus; not a benchmark)")
    print(f"offline taxonomy replay rate: {report.target_detection_rate:.1%} (LLM disabled; not comparable to live taxonomy classification)")
    print(f"report: {output}")

    print("\nCOVERAGE")
    for attack, stats in report.coverage_by_type().items():
        print(
            f"- {attack}: {stats['detected']}/{stats['generated']} security-detected; "
            f"{stats['target_detected']}/{stats['generated']} correctly typed; "
            f"{stats['taxonomy_mismatches']} taxonomy mismatches; "
            f"{stats['bypassed']} bypassed; {stats['evaluation_errors']} errors"
        )

    if report.bypasses:
        print("\nREPLAY BYPASSES")
        for attempt in report.bypasses:
            print(f"- {attempt.variant.variant_id}: {attempt.variant.target_attack_type.value}")
            print(f"  channels: {', '.join(attempt.evaluation.channels) or 'none'}")
            for index, turn in enumerate(attempt.variant.turns, 1):
                print(f"  turn {index}: {turn.replace(chr(10), ' ')[:350]}")


if __name__ == "__main__":
    main()
