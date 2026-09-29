from __future__ import annotations

import base64
import binascii
import codecs
import re
from urllib.parse import unquote

from aegis.models import DecodedArtifact

BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])")
HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){4,}(?![0-9A-Fa-f])")

GENERIC_ENGLISH_WORDS = {
    "the", "and", "you", "your", "to", "of", "is", "this", "that", "for",
    "with", "from", "not", "are", "be", "as", "on", "in", "it", "we", "a",
}


def _printable_ratio(value: str) -> float:
    if not value:
        return 0.0
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in value)
    return printable / len(value)


def _decode_bytes(data: bytes) -> str | None:
    # Obfuscated prompt text is overwhelmingly UTF-8/ASCII. Falling back to
    # arbitrary UTF-16 makes ordinary English tokens (for example,
    # "previous") look like valid printable Base64 decodes.
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _printable_ratio(value) >= 0.9:
        return value
    return None


def decode_url_text(text: str) -> list[DecodedArtifact]:
    decoded = unquote(text)
    if decoded == text:
        return []
    return [DecodedArtifact("url", text, decoded)]


def decode_base64_tokens(text: str) -> list[DecodedArtifact]:
    artifacts: list[DecodedArtifact] = []
    seen: set[str] = set()
    for match in BASE64_TOKEN.finditer(text):
        token = match.group(0)
        if token in seen or len(token) % 4 != 0:
            continue
        seen.add(token)
        try:
            raw = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = _decode_bytes(raw)
        if decoded and decoded != token:
            artifacts.append(DecodedArtifact("base64", token, decoded))
    return artifacts


def decode_hex_tokens(text: str) -> list[DecodedArtifact]:
    artifacts: list[DecodedArtifact] = []
    seen: set[str] = set()
    for match in HEX_TOKEN.finditer(text):
        token = match.group(0)
        if token in seen:
            continue
        seen.add(token)
        try:
            raw = bytes.fromhex(token)
        except ValueError:
            continue
        decoded = _decode_bytes(raw)
        if decoded and decoded != token:
            artifacts.append(DecodedArtifact("hex", token, decoded))
    return artifacts


def _english_score(text: str) -> int:
    words = re.findall(r"[A-Za-z]+", text.lower())
    return sum(word in GENERIC_ENGLISH_WORDS for word in words)


def decode_rot13_candidate(text: str) -> list[DecodedArtifact]:
    if len(text) < 12 or not re.search(r"[A-Za-z]", text):
        return []
    decoded = codecs.decode(text, "rot_13")
    # Generic language heuristic only; this does not classify security intent.
    if _english_score(decoded) >= _english_score(text) + 2:
        return [DecodedArtifact("rot13", text, decoded)]
    return []


def reveal_encoded_content(text: str) -> list[DecodedArtifact]:
    artifacts: list[DecodedArtifact] = []
    artifacts.extend(decode_url_text(text))
    artifacts.extend(decode_base64_tokens(text))
    artifacts.extend(decode_hex_tokens(text))
    artifacts.extend(decode_rot13_candidate(text))

    # De-duplicate exact codec/decoded pairs while preserving order.
    deduped: list[DecodedArtifact] = []
    seen: set[tuple[str, str]] = set()
    for item in artifacts:
        key = (item.codec, item.decoded_text)
        if key not in seen:
            deduped.append(item)
            seen.add(key)
    return deduped
