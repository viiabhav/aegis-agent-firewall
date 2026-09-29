import json
from pathlib import Path


def test_heldout_benchmark_has_nine_categories_and_benign_cases():
    root = Path(__file__).resolve().parents[2]
    payload = json.loads((root / "benchmarks" / "heldout_v2.json").read_text(encoding="utf-8"))
    cases = payload["cases"]
    attack_types = {item["attack_type"] for item in cases if item["label"] == "attack"}
    assert len(attack_types) == 9
    assert sum(item["label"] == "benign" for item in cases) >= 15
    assert all(item["text"] or item["turns"] for item in cases)


def test_benchmark_is_explicitly_not_an_external_accuracy_claim():
    root = Path(__file__).resolve().parents[2]
    payload = json.loads((root / "benchmarks" / "heldout_v2.json").read_text(encoding="utf-8"))
    disclaimer = payload["disclaimer"].lower()
    assert "not" in disclaimer
    assert "benchmark" in disclaimer or "accuracy" in disclaimer
