from __future__ import annotations

from pathlib import Path


def read_text_file(path: Path) -> tuple[str, dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return text, {"filename": path.name, "suffix": path.suffix.lower()}
