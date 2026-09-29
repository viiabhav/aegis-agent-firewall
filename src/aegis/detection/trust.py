from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from aegis.models import IngestedDocument, InputSource

from .rules import EXTERNAL_SOURCES


class TrustLevel(StrEnum):
    TRUSTED_USER = "trusted_user"
    UNTRUSTED_EXTERNAL = "untrusted_external"


@dataclass(slots=True, frozen=True)
class TrustBoundary:
    source_type: InputSource
    level: TrustLevel
    reason: str

    @property
    def is_untrusted(self) -> bool:
        return self.level == TrustLevel.UNTRUSTED_EXTERNAL


def classify_trust(source_type: InputSource) -> TrustBoundary:
    if source_type.value in EXTERNAL_SOURCES:
        return TrustBoundary(
            source_type=source_type,
            level=TrustLevel.UNTRUSTED_EXTERNAL,
            reason="Retrieved/file content is data and must never be treated as authority for the downstream agent.",
        )
    return TrustBoundary(
        source_type=source_type,
        level=TrustLevel.TRUSTED_USER,
        reason="Direct user/plain-text input; still scanned for malicious instructions but not treated as retrieved content.",
    )


def document_trust(document: IngestedDocument) -> TrustBoundary:
    return classify_trust(document.source_type)
