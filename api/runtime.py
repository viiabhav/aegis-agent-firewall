from __future__ import annotations

from functools import lru_cache
import ipaddress
import os
from pathlib import Path
import socket
from threading import RLock
from urllib.parse import urlparse

from dotenv import load_dotenv

from aegis.decision import FirewallEngine
from aegis.detection import GroqJudgeProvider, LLMJudge, SemanticDetector


_LOCK = RLock()
_CONVERSATIONS: dict[str, tuple[tuple[bool, bool], FirewallEngine]] = {}
_MAX_CONVERSATIONS = 64
_ROOT = Path(__file__).resolve().parents[1]
_ENV_FILE = _ROOT / ".env"


def refresh_environment() -> None:
    """Load local, gitignored runtime configuration without exposing secrets to the UI."""
    if _ENV_FILE.is_file():
        load_dotenv(_ENV_FILE, override=False)


refresh_environment()


@lru_cache(maxsize=1)
def semantic_detector() -> SemanticDetector:
    return SemanticDetector()


def llm_judge() -> LLMJudge | None:
    # Do not cache the "not configured" state. This lets a user create .env,
    # click Recheck in the UI, and enable the judge without restarting AEGIS.
    refresh_environment()
    if not os.getenv("GROQ_API_KEY", "").strip():
        return None
    return LLMJudge(GroqJudgeProvider())


def llm_status() -> dict[str, object]:
    refresh_environment()
    configured = bool(os.getenv("GROQ_API_KEY", "").strip())
    return {
        "llm_configured": configured,
        "llm_provider": "groq",
        "llm_model": os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"),
        "llm_env_file_present": _ENV_FILE.is_file(),
        "llm_setup_command": r".\scripts\configure_llm.ps1",
    }


def build_engine(*, use_semantic: bool, use_llm: bool, multiturn: bool) -> FirewallEngine:
    return FirewallEngine(
        semantic_detector=semantic_detector() if use_semantic else None,
        llm_judge=llm_judge() if use_llm else None,
        enable_semantic=use_semantic,
        enable_llm=use_llm,
        enable_multiturn=multiturn,
    )


def conversation_engine(conversation_id: str, *, use_semantic: bool, use_llm: bool) -> FirewallEngine:
    config = (use_semantic, use_llm)
    with _LOCK:
        existing = _CONVERSATIONS.get(conversation_id)
        if existing and existing[0] == config:
            return existing[1]
        if len(_CONVERSATIONS) >= _MAX_CONVERSATIONS:
            oldest = next(iter(_CONVERSATIONS))
            _CONVERSATIONS.pop(oldest, None)
        engine = build_engine(use_semantic=use_semantic, use_llm=use_llm, multiturn=True)
        _CONVERSATIONS[conversation_id] = (config, engine)
        return engine


def reset_conversation(conversation_id: str) -> bool:
    with _LOCK:
        existing = _CONVERSATIONS.pop(conversation_id, None)
    if existing:
        existing[1].reset_conversation()
        return True
    return False


def replay_corpus_path() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "redteam_attack_corpus.json"


def validate_public_url(url: str) -> str:
    """Reject obvious SSRF targets before handing a URL to the web ingestor."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only http:// and https:// URLs are supported")

    host = parsed.hostname.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise ValueError("Local/private URLs are not allowed")

    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ValueError("URL hostname could not be resolved") from exc

    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError("Local/private URLs are not allowed")
    return url


def benchmark_report_path() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "heldout_benchmark_report.json"


def replay_report_path() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "redteam_replay_report.json"
