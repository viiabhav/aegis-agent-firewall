from __future__ import annotations

import unicodedata

ZERO_WIDTH = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero width no-break / BOM
}

# Deliberately small, auditable set of common Greek/Cyrillic lookalikes.
HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "А": "A",  # Cyrillic
        "е": "e", "Е": "E",
        "о": "o", "О": "O",
        "р": "p", "Р": "P",
        "с": "c", "С": "C",
        "х": "x", "Х": "X",
        "у": "y", "У": "Y",
        "і": "i", "І": "I",
        "ј": "j", "Ј": "J",
        "ѕ": "s", "Ѕ": "S",
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z",  # Greek
        "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
        "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
        "Χ": "X", "Υ": "Y",
        "ο": "o", "ρ": "p", "χ": "x", "ι": "i",
    }
)


def canonicalize_unicode(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if ch not in ZERO_WIDTH)
    return text.translate(HOMOGLYPHS)
