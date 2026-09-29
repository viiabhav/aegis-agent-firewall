from __future__ import annotations

from dataclasses import dataclass, field
import math
import re
from typing import Protocol, Sequence

from aegis.models import IngestedDocument, InputSource

from .models import AttackType
from .rules import EXTERNAL_SOURCES
from .semantic_corpus import SEMANTIC_PROTOTYPES, SemanticPrototype


DEFAULT_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_THRESHOLD = 0.62
DEFAULT_MAX_MATCHES = 5


class TextEncoder(Protocol):
    def encode(self, sentences: Sequence[str], **kwargs): ...


@dataclass(slots=True, frozen=True)
class SemanticMatch:
    attack_type: AttackType
    similarity: float
    evidence: str
    prototype_id: str
    prototype_text: str
    start: int
    end: int


@dataclass(slots=True)
class SemanticReport:
    matches: list[SemanticMatch] = field(default_factory=list)
    threshold: float = DEFAULT_THRESHOLD
    model_name: str = DEFAULT_MODEL_NAME

    @property
    def attack_types(self) -> list[AttackType]:
        seen: set[AttackType] = set()
        output: list[AttackType] = []
        for match in self.matches:
            if match.attack_type not in seen:
                seen.add(match.attack_type)
                output.append(match.attack_type)
        return output

    @property
    def max_similarity(self) -> float:
        return max((item.similarity for item in self.matches), default=0.0)


@dataclass(slots=True, frozen=True)
class _Segment:
    text: str
    start: int
    end: int


def _to_vector(value) -> list[float]:
    if hasattr(value, "tolist"):
        value = value.tolist()
    return [float(item) for item in value]


def _normalize(vector: Sequence[float]) -> list[float]:
    norm = math.sqrt(sum(item * item for item in vector))
    if norm <= 1e-12:
        return [0.0 for _ in vector]
    return [item / norm for item in vector]


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    # Vectors are normalized before this function, so dot product is cosine.
    return sum(x * y for x, y in zip(a, b, strict=False))


def _split_segments(text: str, max_chars: int = 520) -> list[_Segment]:
    """Split long input into evidence-sized semantic units while preserving offsets."""
    text = text or ""
    if not text.strip():
        return []

    pieces: list[_Segment] = []
    # Sentence/paragraph-ish boundaries. This is intentionally deterministic and
    # dependency-free; it is not meant to be a linguistic sentence tokenizer.
    boundary = re.compile(r"(?<=[.!?])\s+|\n{1,}")
    cursor = 0
    for match in boundary.finditer(text):
        end = match.start()
        _append_chunked(pieces, text, cursor, end, max_chars)
        cursor = match.end()
    _append_chunked(pieces, text, cursor, len(text), max_chars)

    return [piece for piece in pieces if piece.text.strip()]


def _append_chunked(pieces: list[_Segment], source: str, start: int, end: int, max_chars: int) -> None:
    while start < end and source[start].isspace():
        start += 1
    while end > start and source[end - 1].isspace():
        end -= 1
    if start >= end:
        return

    pos = start
    while pos < end:
        chunk_end = min(end, pos + max_chars)
        if chunk_end < end:
            # Prefer a whitespace break instead of slicing a word.
            break_at = source.rfind(" ", pos, chunk_end)
            if break_at > pos + max_chars // 2:
                chunk_end = break_at
        chunk_text = source[pos:chunk_end].strip()
        if chunk_text:
            actual_start = source.find(chunk_text, pos, chunk_end + 1)
            pieces.append(_Segment(chunk_text, actual_start, actual_start + len(chunk_text)))
        pos = max(chunk_end, pos + 1)
        while pos < end and source[pos].isspace():
            pos += 1


class SemanticDetector:
    """Local sentence-embedding detector against a curated attack prototype corpus.

    The similarity score is a cosine similarity, not a calibrated probability.
    Thresholds should be tuned later on the repository's own labelled evaluation set.
    """

    def __init__(
        self,
        encoder: TextEncoder | None = None,
        *,
        model_name: str = DEFAULT_MODEL_NAME,
        threshold: float = DEFAULT_THRESHOLD,
        prototypes: Sequence[SemanticPrototype] = SEMANTIC_PROTOTYPES,
        max_matches: int = DEFAULT_MAX_MATCHES,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")
        if max_matches < 1:
            raise ValueError("max_matches must be >= 1")
        if not prototypes:
            raise ValueError("at least one semantic prototype is required")

        self.model_name = model_name
        self.threshold = threshold
        self.prototypes = tuple(prototypes)
        self.max_matches = max_matches
        self._encoder = encoder
        self._prototype_vectors: list[list[float]] | None = None

    def _get_encoder(self) -> TextEncoder:
        if self._encoder is None:
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:  # pragma: no cover - exercised on user machine when dependency absent
                raise RuntimeError(
                    'sentence-transformers is required for live semantic scanning. '
                    'Run: python -m pip install -e ".[dev]"'
                ) from exc
            self._encoder = SentenceTransformer(self.model_name)
        return self._encoder

    def _encode(self, texts: Sequence[str]) -> list[list[float]]:
        encoder = self._get_encoder()
        try:
            raw = encoder.encode(texts, normalize_embeddings=True, show_progress_bar=False)
        except TypeError:
            # Keeps the detector injectable for tiny deterministic test encoders.
            raw = encoder.encode(texts)
        if hasattr(raw, "tolist"):
            raw = raw.tolist()
        return [_normalize(_to_vector(vector)) for vector in raw]

    def _prototype_embeddings(self) -> list[list[float]]:
        if self._prototype_vectors is None:
            self._prototype_vectors = self._encode([item.text for item in self.prototypes])
        return self._prototype_vectors

    def scan_document(self, document: IngestedDocument) -> SemanticReport:
        segments = _split_segments(document.normalized.scan_text)
        if not segments:
            return SemanticReport(threshold=self.threshold, model_name=self.model_name)

        segment_vectors = self._encode([segment.text for segment in segments])
        prototype_vectors = self._prototype_embeddings()
        candidates: list[SemanticMatch] = []

        for segment, vector in zip(segments, segment_vectors, strict=True):
            # Keep only the strongest prototype per attack type for each segment.
            per_type: dict[AttackType, SemanticMatch] = {}
            for prototype, prototype_vector in zip(self.prototypes, prototype_vectors, strict=True):
                if (
                    prototype.attack_type == AttackType.INDIRECT_PROMPT_INJECTION
                    and document.source_type.value not in EXTERNAL_SOURCES
                ):
                    continue

                similarity = _cosine(vector, prototype_vector)
                if similarity < self.threshold:
                    continue
                match = SemanticMatch(
                    attack_type=prototype.attack_type,
                    similarity=round(similarity, 4),
                    evidence=segment.text,
                    prototype_id=prototype.prototype_id,
                    prototype_text=prototype.text,
                    start=segment.start,
                    end=segment.end,
                )
                previous = per_type.get(prototype.attack_type)
                if previous is None or match.similarity > previous.similarity:
                    per_type[prototype.attack_type] = match
            candidates.extend(per_type.values())

        # Avoid flooding the caller with repeated segments for the same category.
        strongest_by_type: dict[AttackType, SemanticMatch] = {}
        for item in candidates:
            previous = strongest_by_type.get(item.attack_type)
            if previous is None or item.similarity > previous.similarity:
                strongest_by_type[item.attack_type] = item

        matches = sorted(
            strongest_by_type.values(),
            key=lambda item: (-item.similarity, item.attack_type.value),
        )[: self.max_matches]
        return SemanticReport(matches=matches, threshold=self.threshold, model_name=self.model_name)

    def scan_text(self, text: str, source_type: InputSource = InputSource.USER_MESSAGE) -> SemanticReport:
        from aegis.ingestion.dispatcher import ingest_payload

        document = ingest_payload(text, source_type)
        return self.scan_document(document)
