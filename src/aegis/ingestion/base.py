from __future__ import annotations

from pathlib import Path
from typing import Protocol

from aegis.models import InputSource


class FileParser(Protocol):
    source_type: InputSource

    def parse(self, path: Path) -> tuple[str, dict]: ...
