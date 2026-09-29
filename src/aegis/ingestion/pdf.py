from __future__ import annotations

from pathlib import Path
from pypdf import PdfReader


def extract_pdf_text(path: Path) -> tuple[str, dict]:
    reader = PdfReader(str(path))
    pages: list[str] = []
    for index, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        pages.append(f"[page:{index}]\n{text}")
    return "\n\n".join(pages), {
        "filename": path.name,
        "pages": len(reader.pages),
        "parser": "pypdf",
    }
