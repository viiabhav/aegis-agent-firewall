from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx

from .html import extract_html_text


def _validate_public_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only http/https URLs are supported")

    if parsed.hostname.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("Localhost URLs are not allowed")

    # Basic SSRF guard for the prototype: reject resolved private/loopback/link-local IPs.
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve URL host: {parsed.hostname}") from exc

    for item in addresses:
        ip = ipaddress.ip_address(item[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("Private or non-public network targets are not allowed")


def fetch_web_page(url: str, *, timeout_seconds: float = 10.0, max_bytes: int = 2_000_000) -> tuple[str, dict]:
    _validate_public_http_url(url)
    with httpx.Client(follow_redirects=True, timeout=timeout_seconds) as client:
        response = client.get(url, headers={"User-Agent": "Aegis-Hackathon-Prototype/0.1"})
        response.raise_for_status()
        content = response.content
        if len(content) > max_bytes:
            raise ValueError(f"Web response exceeds {max_bytes} bytes")
        content_type = response.headers.get("content-type", "")

    if "html" in content_type.lower() or response.text.lstrip().startswith(("<!DOCTYPE", "<html", "<HTML")):
        text, parser_meta = extract_html_text(response.text)
    else:
        text, parser_meta = response.text, {"parser": "plain-web-text"}

    return text, {
        "url": str(response.url),
        "status_code": response.status_code,
        "content_type": content_type,
        **parser_meta,
    }
