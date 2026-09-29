from __future__ import annotations

from pathlib import Path
from PIL import Image
import pytesseract


def extract_image_text(path: Path) -> tuple[str, dict]:
    with Image.open(path) as image:
        text = pytesseract.image_to_string(image)
        width, height = image.size
    return text, {
        "filename": path.name,
        "parser": "tesseract",
        "width": width,
        "height": height,
    }
