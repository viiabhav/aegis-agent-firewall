from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from aegis.detection import AttackType
from aegis.models import InputSource

from .redteam import AttackVariant, FirewallEvaluator, RedTeamAttempt, RedTeamReport


@dataclass(slots=True, frozen=True)
class ReplayCorpus:
    schema_version: str
    name: str
    description: str
    disclaimer: str
    origin: str
    cases: tuple[AttackVariant, ...]

    @property
    def categories(self) -> tuple[AttackType, ...]:
        found = {case.target_attack_type for case in self.cases}
        return tuple(item for item in AttackType if item in found)

    @classmethod
    def load(cls, path: str | Path) -> "ReplayCorpus":
        source = Path(path)
        raw = json.loads(source.read_text(encoding="utf-8"))
        cases: list[AttackVariant] = []
        seen_ids: set[str] = set()
        for item in raw.get("cases", []):
            variant_id = str(item["variant_id"])
            if variant_id in seen_ids:
                raise ValueError(f"duplicate replay variant_id: {variant_id}")
            seen_ids.add(variant_id)
            turns = tuple(str(turn) for turn in item["turns"] if str(turn).strip())
            if not turns:
                raise ValueError(f"replay case {variant_id} has no turns")
            cases.append(
                AttackVariant(
                    variant_id=variant_id,
                    target_attack_type=AttackType(str(item["target_attack_type"])),
                    strategy=str(item.get("strategy", "historical replay case")),
                    source_type=InputSource(str(item.get("source_type", "user_message"))),
                    turns=turns,
                    notes=str(item.get("notes", "")),
                    round_index=int(item.get("round_index", 0)),
                )
            )
        corpus = cls(
            schema_version=str(raw.get("schema_version", "1.0")),
            name=str(raw.get("name", source.stem)),
            description=str(raw.get("description", "")),
            disclaimer=str(raw.get("disclaimer", "")),
            origin=str(raw.get("origin", "unknown")),
            cases=tuple(cases),
        )
        missing = [item.value for item in AttackType if item not in corpus.categories]
        if missing:
            raise ValueError("replay corpus is missing attack categories: " + ", ".join(missing))
        return corpus


@dataclass(slots=True)
class ReplayRunResult:
    corpus: ReplayCorpus
    report: RedTeamReport
    llm_judge_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": "deterministic_regression_replay",
            "provider_generation_required": False,
            "llm_judge_enabled": self.llm_judge_enabled,
            "corpus": {
                "schema_version": self.corpus.schema_version,
                "name": self.corpus.name,
                "description": self.corpus.description,
                "disclaimer": self.corpus.disclaimer,
                "origin": self.corpus.origin,
                "case_count": len(self.corpus.cases),
                "categories_covered": len(self.corpus.categories),
                "categories_total": len(AttackType),
            },
            "redteam": self.report.to_dict(),
        }

    def save_json(self, path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return output


def run_replay(corpus: ReplayCorpus, evaluator: FirewallEvaluator) -> ReplayRunResult:
    requested = list(corpus.categories)
    report = RedTeamReport(requested_attack_types=requested, rounds_completed=1)
    for variant in corpus.cases:
        evaluation = evaluator.evaluate(variant)
        report.attempts.append(RedTeamAttempt(variant=variant, evaluation=evaluation))
    return ReplayRunResult(corpus=corpus, report=report, llm_judge_enabled=evaluator.llm_judge is not None)
