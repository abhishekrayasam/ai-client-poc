"""
AI endpoint scope + provider-specific prompt extraction.

The agent only inspects traffic to known AI hosts (per the user's "AI prompt
endpoints only" scope). For each provider we know where the user's prompt lives
in the request JSON; anything we can't parse falls back to scanning the raw
request body with the same detection engine, so PII in an unexpected shape is
still caught.
"""

import json
import logging
from typing import Iterable, List, Optional

log = logging.getLogger("promptfirewall.hosts")

# Hostnames whose POST bodies we inspect. Suffix match (so api.openai.com and
# chatgpt.com both hit). Extend via config.json -> "ai_hosts".
AI_HOSTS = (
    "chatgpt.com",
    "chat.openai.com",
    "api.openai.com",
    "claude.ai",
    "api.anthropic.com",
    "gemini.google.com",
    "generativelanguage.googleapis.com",
    "copilot.microsoft.com",
    "api.cohere.ai",
    "api.cohere.com",
)


def is_ai_host(host: str, extra_hosts: Iterable[str] = ()) -> bool:
    """True if ``host`` is (a subdomain of) a known AI endpoint."""
    if not host:
        return False
    host = host.lower()
    for h in list(AI_HOSTS) + list(extra_hosts or ()):
        h = h.lower()
        if host == h or host.endswith("." + h):
            return True
    return False


def _collect_strings(node, out: List[str]) -> None:
    """Recursively pull every string value out of a JSON-ish structure.

    Used as a provider-agnostic extractor: chat APIs bury the prompt in various
    shapes (messages[].content may itself be a list of {type,text} parts), and
    scanning all leaf strings guarantees we see the user's text regardless of
    schema drift.
    """
    if isinstance(node, str):
        if node.strip():
            out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _collect_strings(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_strings(v, out)


def _openai_like(body: dict) -> List[str]:
    """OpenAI / Anthropic / Cohere chat shape: messages[].content."""
    texts: List[str] = []
    for msg in body.get("messages", []) or []:
        if isinstance(msg, dict) and msg.get("role") in (None, "user", "system"):
            _collect_strings(msg.get("content"), texts)
    # Anthropic sometimes uses top-level "system"; Cohere uses "message".
    _collect_strings(body.get("system"), texts)
    if isinstance(body.get("message"), str):
        texts.append(body["message"])
    if isinstance(body.get("prompt"), str):
        texts.append(body["prompt"])
    return texts


def _gemini_like(body: dict) -> List[str]:
    """Gemini shape: contents[].parts[].text."""
    texts: List[str] = []
    for content in body.get("contents", []) or []:
        if isinstance(content, dict):
            for part in content.get("parts", []) or []:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    texts.append(part["text"])
    return texts


def extract_prompt(host: str, raw_body: bytes) -> Optional[str]:
    """Return the user-authored prompt text from a request body, or None.

    Strategy: parse JSON and use provider-specific pullers; if those come up
    empty (or the body isn't JSON we recognize), fall back to every leaf string
    in the JSON, and finally to the decoded raw body. Returning a best-effort
    string is intentional -- the detection engine tolerates extra surrounding
    text, and false-scanning is safer than missing a prompt.
    """
    if not raw_body:
        return None

    text_body = raw_body.decode("utf-8", errors="replace")

    try:
        body = json.loads(text_body)
    except (ValueError, TypeError):
        # Not JSON (e.g. form-encoded / multipart) -> scan raw text.
        return text_body

    if not isinstance(body, dict):
        # JSON array or scalar -> scan all strings within it.
        collected: List[str] = []
        _collect_strings(body, collected)
        return "\n".join(collected) if collected else text_body

    host_l = (host or "").lower()
    parts: List[str] = []

    if "generativelanguage.googleapis.com" in host_l or "gemini" in host_l:
        parts = _gemini_like(body)
    else:
        parts = _openai_like(body)

    if not parts:
        # Unknown schema -> scan every leaf string so we never silently miss.
        _collect_strings(body, parts)

    result = "\n".join(p for p in parts if p and p.strip())
    return result or text_body