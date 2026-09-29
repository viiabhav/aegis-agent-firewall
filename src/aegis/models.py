from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class InputSource(StrEnum):
    USER_MESSAGE = "user_message"
    WEB_PAGE = "web_page"
    PDF = "pdf"
    EMAIL = "email"
    MARKDOWN = "markdown"
    HTML = "html"
    DOCX = "docx"
    API_RESPONSE = "api_response"
    OCR_TEXT = "ocr_text"
    SOURCE_CODE = "source_code"
    IMAGE = "image"
    PLAIN_TEXT = "plain_text"


@dataclass(slots=True)
class DecodedArtifact:
    codec: str
    source_fragment: str
    decoded_text: str


@dataclass(slots=True)
class NormalizationResult:
    original_text: str
    canonical_text: str
    decoded_artifacts: list[DecodedArtifact] = field(default_factory=list)

    @property
    def scan_text(self) -> str:
        """Text future detectors should scan without losing original context."""
        if not self.decoded_artifacts:
            return self.canonical_text
        revealed = "\n".join(
            f"[decoded:{item.codec}] {item.decoded_text}"
            for item in self.decoded_artifacts
        )
        return f"{self.canonical_text}\n{revealed}"


@dataclass(slots=True)
class IngestedDocument:
    source_type: InputSource
    raw_text: str
    normalized: NormalizationResult
    metadata: dict[str, Any] = field(default_factory=dict)
