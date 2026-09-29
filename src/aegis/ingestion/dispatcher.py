from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.models import IngestedDocument, InputSource
from aegis.normalization import normalize_text

from .api import extract_api_text
from .docx import extract_docx_text
from .email import extract_email_file, extract_email_text
from .html import extract_html_text
from .image import extract_image_text
from .pdf import extract_pdf_text
from .text import read_text_file
from .web import fetch_web_page

TEXT_SUFFIX_TO_SOURCE = {
    ".txt": InputSource.PLAIN_TEXT,
    ".md": InputSource.MARKDOWN,
    ".markdown": InputSource.MARKDOWN,
    ".py": InputSource.SOURCE_CODE,
    ".js": InputSource.SOURCE_CODE,
    ".ts": InputSource.SOURCE_CODE,
    ".java": InputSource.SOURCE_CODE,
    ".go": InputSource.SOURCE_CODE,
    ".rs": InputSource.SOURCE_CODE,
    ".cpp": InputSource.SOURCE_CODE,
    ".c": InputSource.SOURCE_CODE,
    ".cs": InputSource.SOURCE_CODE,
    ".sql": InputSource.SOURCE_CODE,
    ".json": InputSource.API_RESPONSE,
}

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".tif", ".tiff", ".bmp"}


def _build(source_type: InputSource, raw_text: str, metadata: dict[str, Any] | None = None) -> IngestedDocument:
    return IngestedDocument(
        source_type=source_type,
        raw_text=raw_text,
        normalized=normalize_text(raw_text),
        metadata=metadata or {},
    )


def ingest_payload(payload: Any, source_type: InputSource) -> IngestedDocument:
    if source_type == InputSource.API_RESPONSE:
        text, metadata = extract_api_text(payload)
    elif source_type == InputSource.HTML:
        if not isinstance(payload, str):
            raise TypeError("HTML payload must be a string")
        text, metadata = extract_html_text(payload)
    elif source_type == InputSource.EMAIL:
        if not isinstance(payload, str):
            raise TypeError("Email payload must be RFC 822 text")
        text, metadata = extract_email_text(payload)
    elif source_type in {
        InputSource.USER_MESSAGE,
        InputSource.MARKDOWN,
        InputSource.OCR_TEXT,
        InputSource.SOURCE_CODE,
        InputSource.PLAIN_TEXT,
    }:
        if not isinstance(payload, str):
            raise TypeError(f"{source_type.value} payload must be a string")
        text, metadata = payload, {}
    else:
        raise ValueError(f"Use ingest_file/ingest_url for source type {source_type.value}")

    return _build(source_type, text, metadata)


def ingest_file(path: str | Path) -> IngestedDocument:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)

    suffix = path.suffix.lower()
    if suffix == ".pdf":
        text, metadata = extract_pdf_text(path)
        source = InputSource.PDF
    elif suffix == ".docx":
        text, metadata = extract_docx_text(path)
        source = InputSource.DOCX
    elif suffix in {".eml", ".email"}:
        text, metadata = extract_email_file(path)
        source = InputSource.EMAIL
    elif suffix in {".html", ".htm"}:
        raw = path.read_text(encoding="utf-8", errors="replace")
        text, metadata = extract_html_text(raw)
        metadata["filename"] = path.name
        source = InputSource.HTML
    elif suffix in IMAGE_SUFFIXES:
        text, metadata = extract_image_text(path)
        source = InputSource.IMAGE
    elif suffix in TEXT_SUFFIX_TO_SOURCE:
        text, metadata = read_text_file(path)
        source = TEXT_SUFFIX_TO_SOURCE[suffix]
    else:
        raise ValueError(f"Unsupported file type: {suffix or '<no suffix>'}")

    return _build(source, text, metadata)


def ingest_url(url: str) -> IngestedDocument:
    text, metadata = fetch_web_page(url)
    return _build(InputSource.WEB_PAGE, text, metadata)
