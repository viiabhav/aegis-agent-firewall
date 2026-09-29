from __future__ import annotations

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    content: str = Field(min_length=1, max_length=500_000)
    source_type: str = "user_message"
    use_semantic: bool = True
    use_llm: bool = False
    conversation_id: str | None = Field(default=None, max_length=128)
    track_conversation: bool = False


class UrlScanRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    use_semantic: bool = True
    use_llm: bool = False


class ReplayRequest(BaseModel):
    use_semantic: bool = True


class ResetConversationRequest(BaseModel):
    conversation_id: str = Field(min_length=1, max_length=128)


class LiveRedTeamRequest(BaseModel):
    attack_types: list[str] = Field(
        default_factory=lambda: [
            "instruction_override",
            "tool_abuse",
            "multi_step_jailbreak",
            "indirect_prompt_injection",
        ],
        min_length=1,
        max_length=4,
    )
    variants_per_type: int = Field(default=1, ge=1, le=1)
    rounds: int = Field(default=1, ge=1, le=1)

