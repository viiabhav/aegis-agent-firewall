from __future__ import annotations

from bs4 import BeautifulSoup, Comment


def extract_html_text(html: str) -> tuple[str, dict]:
    soup = BeautifulSoup(html, "html.parser")

    # Scripts/styles are not normally part of the content sent to an LLM.
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    parts: list[str] = []
    visible = soup.get_text("\n", strip=True)
    if visible:
        parts.append(visible)

    comments = [str(node).strip() for node in soup.find_all(string=lambda x: isinstance(x, Comment))]
    comments = [c for c in comments if c]
    if comments:
        parts.extend(f"[html-comment] {c}" for c in comments)

    for tag in soup.find_all(True):
        for attr in ("alt", "title", "aria-label"):
            value = tag.get(attr)
            if value:
                parts.append(f"[html-{attr}] {value}")
        if tag.name == "meta" and tag.get("content"):
            parts.append(f"[html-meta] {tag.get('content')}")

    return "\n".join(parts), {"parser": "beautifulsoup4"}
