from __future__ import annotations

from email import policy
from email.parser import BytesParser, Parser
from pathlib import Path

from .html import extract_html_text


def _extract_message(message) -> tuple[str, dict]:
    parts: list[str] = []
    metadata = {
        "subject": message.get("subject", ""),
        "from": message.get("from", ""),
        "to": message.get("to", ""),
    }

    if metadata["subject"]:
        parts.append(f"[subject] {metadata['subject']}")

    if message.is_multipart():
        for item in message.walk():
            disposition = item.get_content_disposition()
            if disposition == "attachment":
                parts.append(f"[attachment] {item.get_filename() or 'unnamed'}")
                continue
            content_type = item.get_content_type()
            if content_type == "text/plain":
                payload = item.get_content()
                if payload:
                    parts.append(str(payload))
            elif content_type == "text/html":
                payload = item.get_content()
                if payload:
                    extracted, _ = extract_html_text(str(payload))
                    parts.append(extracted)
    else:
        payload = message.get_content()
        if message.get_content_type() == "text/html":
            payload, _ = extract_html_text(str(payload))
        parts.append(str(payload))

    return "\n".join(part for part in parts if part.strip()), metadata


def extract_email_text(raw_email: str) -> tuple[str, dict]:
    message = Parser(policy=policy.default).parsestr(raw_email)
    return _extract_message(message)


def extract_email_file(path: Path) -> tuple[str, dict]:
    with path.open("rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)
    text, metadata = _extract_message(message)
    metadata["filename"] = path.name
    return text, metadata
