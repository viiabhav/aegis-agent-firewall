from __future__ import annotations

import json
from pathlib import Path

from aegis.agents import FirewallEvaluator, ReplayCorpus, run_replay
from aegis.detection import AttackType


CORPUS = Path("artifacts/redteam_attack_corpus.json")


def test_replay_corpus_covers_all_nine_attack_types():
    corpus = ReplayCorpus.load(CORPUS)
    assert len(corpus.cases) == 27
    assert set(corpus.categories) == set(AttackType)
    counts = {item: 0 for item in AttackType}
    for case in corpus.cases:
        counts[case.target_attack_type] += 1
    assert set(counts.values()) == {3}


def test_replay_does_not_require_an_llm_provider_or_api_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    corpus = ReplayCorpus.load(CORPUS)
    evaluator = FirewallEvaluator(
        semantic_detector=None,
        llm_judge=None,
        count_escalation_without_llm=True,
    )
    result = run_replay(corpus, evaluator)
    assert result.llm_judge_enabled is False
    assert result.to_dict()["provider_generation_required"] is False
    assert result.report.generated_count == 27
    assert result.report.evaluation_error_count == 0


def test_replay_report_persists_mode_and_disclaimer(tmp_path):
    corpus = ReplayCorpus.load(CORPUS)
    evaluator = FirewallEvaluator(
        semantic_detector=None,
        llm_judge=None,
        count_escalation_without_llm=True,
    )
    result = run_replay(corpus, evaluator)
    output = result.save_json(tmp_path / "report.json")
    raw = json.loads(output.read_text(encoding="utf-8"))
    assert raw["mode"] == "deterministic_regression_replay"
    assert raw["provider_generation_required"] is False
    assert raw["llm_judge_enabled"] is False
    assert raw["corpus"]["categories_covered"] == 9
    assert "not an independent benchmark" in raw["corpus"]["disclaimer"].lower()


def test_offline_escalation_is_a_security_signal_not_a_fake_taxonomy_label():
    corpus = ReplayCorpus.load(CORPUS)
    case = next(item for item in corpus.cases if item.variant_id == "replay.secret_extraction.01")
    evaluator = FirewallEvaluator(
        semantic_detector=None,
        llm_judge=None,
        count_escalation_without_llm=True,
    )
    result = evaluator.evaluate(case)
    assert result.detected is True
    assert "llm_escalation_policy" in result.channels
    # Replay can prove "would escalate" without pretending an unavailable LLM
    # produced a classification.
    assert result.llm_attack is False


def test_offline_replay_catches_need_placeholder_credential_requests():
    corpus = ReplayCorpus.load(CORPUS)
    evaluator = FirewallEvaluator(
        semantic_detector=None,
        llm_judge=None,
        count_escalation_without_llm=True,
    )
    for variant_id in ("replay.credential_theft.02", "replay.credential_theft.03"):
        case = next(item for item in corpus.cases if item.variant_id == variant_id)
        result = evaluator.evaluate(case)
        assert result.detected is True
        assert "llm_escalation_policy" in result.channels
