from aegis.agents.redteam import GENERATOR_SYSTEM_PROMPT


def test_generator_prompt_forbids_simulated_assistant_responses():
    lower = GENERATOR_SYSTEM_PROMPT.lower()
    assert "attacker-controlled incoming content" in lower
    assert "never simulate or include an assistant/model response" in lower
