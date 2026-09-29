from __future__ import annotations

from collections import Counter

import pytest

from aegis.detection import AttackType, SemanticDetector
from aegis.detection.semantic_corpus import SEMANTIC_PROTOTYPES, SemanticPrototype
from aegis.ingestion import ingest_payload
from aegis.models import InputSource


class LookupEncoder:
    def __init__(self, vectors: dict[str, list[float]]):
        self.vectors = vectors
        self.calls: list[list[str]] = []

    def encode(self, sentences, **kwargs):
        items = list(sentences)
        self.calls.append(items)
        return [self.vectors[item] for item in items]


def proto(pid: str, attack: AttackType, text: str) -> SemanticPrototype:
    return SemanticPrototype(pid, attack, text)


def test_curated_corpus_covers_all_nine_attack_types():
    assert {item.attack_type for item in SEMANTIC_PROTOTYPES} == set(AttackType)


def test_curated_corpus_has_five_seeds_per_attack_type():
    counts = Counter(item.attack_type for item in SEMANTIC_PROTOTYPES)
    assert all(counts[attack] >= 5 for attack in AttackType)


def test_exact_semantic_match_is_returned():
    p = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "prototype")
    encoder = LookupEncoder({"prototype": [1, 0], "query": [1, 0]})
    report = SemanticDetector(encoder, prototypes=[p], threshold=0.6).scan_text("query")
    assert report.attack_types == [AttackType.INSTRUCTION_OVERRIDE]
    assert report.matches[0].similarity == 1.0


def test_below_threshold_is_filtered():
    p = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "prototype")
    encoder = LookupEncoder({"prototype": [1, 0], "query": [0, 1]})
    report = SemanticDetector(encoder, prototypes=[p], threshold=0.6).scan_text("query")
    assert report.matches == []


def test_threshold_is_inclusive():
    p = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "prototype")
    encoder = LookupEncoder({"prototype": [1, 0], "query": [0.6, 0.8]})
    report = SemanticDetector(encoder, prototypes=[p], threshold=0.6).scan_text("query")
    assert report.matches[0].similarity == 0.6


def test_invalid_threshold_rejected():
    with pytest.raises(ValueError):
        SemanticDetector(LookupEncoder({}), threshold=1.1)


def test_empty_prototype_corpus_rejected():
    with pytest.raises(ValueError):
        SemanticDetector(LookupEncoder({}), prototypes=[])


def test_invalid_max_matches_rejected():
    with pytest.raises(ValueError):
        SemanticDetector(LookupEncoder({}), max_matches=0)


def test_strongest_prototype_wins_within_same_attack_type():
    p1 = proto("override.weak", AttackType.INSTRUCTION_OVERRIDE, "weak")
    p2 = proto("override.strong", AttackType.INSTRUCTION_OVERRIDE, "strong")
    encoder = LookupEncoder({
        "weak": [1, 0],
        "strong": [0, 1],
        "query": [0.2, 0.98],
    })
    report = SemanticDetector(encoder, prototypes=[p1, p2], threshold=0.1).scan_text("query")
    assert len(report.matches) == 1
    assert report.matches[0].prototype_id == "override.strong"


def test_distinct_attack_types_can_both_match():
    p1 = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "override")
    p2 = proto("secret.test", AttackType.SECRET_EXTRACTION, "secret")
    encoder = LookupEncoder({
        "override": [1, 0],
        "secret": [0.8, 0.6],
        "query": [1, 0],
    })
    report = SemanticDetector(encoder, prototypes=[p1, p2], threshold=0.75).scan_text("query")
    assert set(report.attack_types) == {AttackType.INSTRUCTION_OVERRIDE, AttackType.SECRET_EXTRACTION}


def test_matches_sorted_by_similarity():
    p1 = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "override")
    p2 = proto("secret.test", AttackType.SECRET_EXTRACTION, "secret")
    encoder = LookupEncoder({
        "override": [0.8, 0.6],
        "secret": [1, 0],
        "query": [1, 0],
    })
    report = SemanticDetector(encoder, prototypes=[p1, p2], threshold=0.5).scan_text("query")
    assert [m.attack_type for m in report.matches] == [AttackType.SECRET_EXTRACTION, AttackType.INSTRUCTION_OVERRIDE]


def test_max_matches_caps_output():
    prototypes = [
        proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "a"),
        proto("secret.test", AttackType.SECRET_EXTRACTION, "b"),
        proto("tool.test", AttackType.TOOL_ABUSE, "c"),
    ]
    encoder = LookupEncoder({"a": [1, 0], "b": [1, 0], "c": [1, 0], "query": [1, 0]})
    report = SemanticDetector(encoder, prototypes=prototypes, threshold=0.5, max_matches=2).scan_text("query")
    assert len(report.matches) == 2


def test_indirect_prototype_ignored_for_direct_user_message():
    p = proto("indirect.test", AttackType.INDIRECT_PROMPT_INJECTION, "page instruction")
    encoder = LookupEncoder({"page instruction": [1, 0], "query": [1, 0]})
    report = SemanticDetector(encoder, prototypes=[p], threshold=0.5).scan_text("query", InputSource.USER_MESSAGE)
    assert report.matches == []


@pytest.mark.parametrize(
    "source",
    [InputSource.WEB_PAGE, InputSource.PDF, InputSource.EMAIL, InputSource.HTML, InputSource.API_RESPONSE, InputSource.IMAGE],
)
def test_indirect_prototype_enabled_for_untrusted_external_sources(source: InputSource):
    p = proto("indirect.test", AttackType.INDIRECT_PROMPT_INJECTION, "page instruction")
    encoder = LookupEncoder({"page instruction": [1, 0], "query": [1, 0]})
    # Build a plain document then set source type to isolate trust-boundary behavior
    # without file/network dependencies in this unit test.
    doc = ingest_payload("query", InputSource.PLAIN_TEXT)
    doc.source_type = source
    report = SemanticDetector(encoder, prototypes=[p], threshold=0.5).scan_document(doc)
    assert report.attack_types == [AttackType.INDIRECT_PROMPT_INJECTION]


def test_empty_text_returns_empty_report_without_encoding():
    p = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "prototype")
    encoder = LookupEncoder({"prototype": [1, 0]})
    report = SemanticDetector(encoder, prototypes=[p]).scan_text("   ")
    assert report.matches == []
    assert encoder.calls == []


def test_prototype_embeddings_are_cached_between_scans():
    p = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "prototype")
    encoder = LookupEncoder({"prototype": [1, 0], "first": [1, 0], "second": [1, 0]})
    detector = SemanticDetector(encoder, prototypes=[p], threshold=0.5)
    detector.scan_text("first")
    detector.scan_text("second")
    prototype_calls = [call for call in encoder.calls if call == ["prototype"]]
    assert len(prototype_calls) == 1


def test_report_exposes_model_name_and_threshold():
    p = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "prototype")
    encoder = LookupEncoder({"prototype": [1, 0], "query": [1, 0]})
    report = SemanticDetector(
        encoder,
        prototypes=[p],
        threshold=0.73,
        model_name="test-model",
    ).scan_text("query")
    assert report.threshold == 0.73
    assert report.model_name == "test-model"


def test_evidence_preserves_segment_offsets():
    first = "Normal introduction."
    second = "Suspicious semantic sentence"
    text = first + " " + second + "."
    p = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "prototype")
    encoder = LookupEncoder({
        "prototype": [1, 0],
        "Normal introduction.": [0, 1],
        "Suspicious semantic sentence.": [1, 0],
    })
    report = SemanticDetector(encoder, prototypes=[p], threshold=0.8).scan_text(text)
    match = report.matches[0]
    assert match.evidence == "Suspicious semantic sentence."
    assert text[match.start:match.end] == match.evidence


def test_long_segment_is_chunked_and_evidence_is_bounded():
    long_prefix = "safe " * 130
    target = "semantic target"
    text = long_prefix + target
    p = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "prototype")

    class TargetEncoder:
        def encode(self, sentences, **kwargs):
            output = []
            for sentence in sentences:
                if sentence == "prototype" or "semantic target" in sentence:
                    output.append([1, 0])
                else:
                    output.append([0, 1])
            return output

    report = SemanticDetector(TargetEncoder(), prototypes=[p], threshold=0.8).scan_text(text)
    assert report.matches
    assert len(report.matches[0].evidence) <= 520
    assert "semantic target" in report.matches[0].evidence


def test_zero_vector_does_not_crash_or_match():
    p = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "prototype")
    encoder = LookupEncoder({"prototype": [1, 0], "query": [0, 0]})
    report = SemanticDetector(encoder, prototypes=[p], threshold=0.1).scan_text("query")
    assert report.matches == []


def test_negative_similarity_is_filtered():
    p = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "prototype")
    encoder = LookupEncoder({"prototype": [1, 0], "query": [-1, 0]})
    report = SemanticDetector(encoder, prototypes=[p], threshold=0.1).scan_text("query")
    assert report.matches == []


def test_similarity_is_cosine_not_raw_dot_product():
    p = proto("override.test", AttackType.INSTRUCTION_OVERRIDE, "prototype")
    encoder = LookupEncoder({"prototype": [10, 0], "query": [3, 4]})
    report = SemanticDetector(encoder, prototypes=[p], threshold=0.59).scan_text("query")
    assert report.matches[0].similarity == 0.6


def test_strongest_match_per_type_is_retained_across_multiple_segments():
    p = proto("secret.test", AttackType.SECRET_EXTRACTION, "prototype")
    encoder = LookupEncoder({
        "prototype": [1, 0],
        "First sentence.": [0.7, 0.714142842],
        "Second sentence.": [1, 0],
    })
    report = SemanticDetector(encoder, prototypes=[p], threshold=0.6).scan_text("First sentence. Second sentence.")
    assert len(report.matches) == 1
    assert report.matches[0].evidence == "Second sentence."
    assert report.matches[0].similarity == 1.0
