from typing import Any

from aegis.agents.redteam import GroqAttackGenerator
from aegis.detection import AttackType


class WrongCategoryUnlessSchemaRestrictedProvider:
    def __init__(self) -> None:
        self.enums: list[list[str]] = []

    def complete(self, *, system_prompt: str, payload: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
        enum = schema["properties"]["variants"]["items"]["properties"]["attack_type"]["enum"]
        self.enums.append(list(enum))
        attack = enum[0]
        source = "email" if attack == "indirect_prompt_injection" else "user_message"
        turns = [f"generated-{attack}"]
        if attack == "multi_step_jailbreak":
            turns.append("follow-up")
        return {
            "variants": [{
                "attack_type": attack,
                "strategy": "schema constrained",
                "source_type": source,
                "turns": turns,
                "notes": "test",
            }]
        }


def test_generator_schema_limits_attack_enum_to_requested_batch():
    provider = WrongCategoryUnlessSchemaRestrictedProvider()
    generator = GroqAttackGenerator(provider, max_categories_per_call=2, max_refill_calls=1)
    requested = [AttackType.ROLE_CHANGE, AttackType.INDIRECT_PROMPT_INJECTION]

    variants = generator.generate(requested, variants_per_type=1, round_index=1)

    assert {v.target_attack_type for v in variants} == set(requested)
    assert all(set(enum).issubset({item.value for item in requested}) for enum in provider.enums)
    # A dedicated refill must constrain the enum to exactly one missing category when needed.
    assert all(enum for enum in provider.enums)
