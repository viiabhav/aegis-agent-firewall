from __future__ import annotations

from aegis.models import NormalizationResult
from .decoders import reveal_encoded_content
from .unicode import canonicalize_unicode


def normalize_text(text: str) -> NormalizationResult:
    if not isinstance(text, str):
        raise TypeError("normalize_text expects a string")

    canonical = canonicalize_unicode(text)
    artifacts = reveal_encoded_content(canonical)

    # Canonicalize revealed text too, so downstream scanners see one text form.
    for artifact in artifacts:
        artifact.decoded_text = canonicalize_unicode(artifact.decoded_text)

    return NormalizationResult(
        original_text=text,
        canonical_text=canonical,
        decoded_artifacts=artifacts,
    )
