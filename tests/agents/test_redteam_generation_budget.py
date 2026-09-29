from __future__ import annotations

from typing import Any

from aegis.agents.redteam import GroqAttackGenerator
from aegis.detection import AttackType


class RecordingProvider:
    def __init__(self, fail_multi: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.fail_multi = fail_multi

    def complete(self, *, system_prompt: str, payload: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
        requested = list(payload["requested_attack_types"])
        self.calls.append(requested)
        if self.fail_multi and len(requested) > 1:
            raise RuntimeError("simulated oversized batch")
        variants = []
        count = int(payload["variants_per_type"])
        for attack in requested:
            for i in range(count):
                source = "email" if attack == "indirect_prompt_injection" else "user_message"
                turns = [f"payload-{attack}-{i}"]
                if attack == "multi_step_jailbreak":
                    turns.append(f"follow-up-{i}")
                variants.append(
                    {
                        "attack_type": attack,
                        "strategy": f"strategy-{i}",
                        "source_type": source,
                        "turns": turns,
                        "notes": "test",
                    }
                )
        return {"variants": variants}


def test_generator_chunks_large_taxonomy_batches() -> None:
    provider = RecordingProvider()
    generator = GroqAttackGenerator(provider, max_categories_per_call=3)
    variants = generator.generate(list(AttackType), variants_per_type=2, round_index=1)

    assert len(variants) == len(list(AttackType)) * 2
    assert provider.calls
    assert max(len(call) for call in provider.calls) <= 3


def test_generator_recovers_failed_multi_category_batches_with_single_category_refills() -> None:
    provider = RecordingProvider(fail_multi=True)
    generator = GroqAttackGenerator(provider, max_categories_per_call=3, max_refill_calls=1)
    requested = [
        AttackType.INSTRUCTION_OVERRIDE,
        AttackType.ROLE_CHANGE,
        AttackType.SECRET_EXTRACTION,
    ]

    variants = generator.generate(requested, variants_per_type=1, round_index=1)

    assert len(variants) == 3
    assert any(len(call) > 1 for call in provider.calls)
    assert sum(1 for call in provider.calls if len(call) == 1) == 3
