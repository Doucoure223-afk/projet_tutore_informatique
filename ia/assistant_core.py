"""Input and context boundaries for the local CyberShield LLM assistant."""

from __future__ import annotations

import json
import math
import re
from typing import Any

MAX_QUESTION_CHARS = 1200
MAX_RECENT_EVENTS = 8
ALLOWED_ACTIONS = {"BLOCKED", "BLOCKED_BY_AI", "ALLOWED", "MONITORED"}
ALLOWED_SOURCES = {"heuristic", "ai", "mlp", "ip_policy"}
ALLOWED_PAGES = {"dashboard", "lab", "ip-rules", "assistant"}


def clean_question(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("La question doit être du texte.")
    question = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", value).strip()
    question = re.sub(r"\b(authorization|cookie|set-cookie)\s*:\s*[^\r\n]*", r"\1: [REDACTED]", question, flags=re.I)
    question = re.sub(r"\b(password|passwd|pwd|token|secret|api[_-]?key|csrf[_-]?token|totp|otp)\s*([:=])\s*(?:\"[^\"]*\"|'[^']*'|[^&\s,;]+)", r"\1\2[REDACTED]", question, flags=re.I)
    question = re.sub(r"\b(?:\d[ -]?){13,19}\b", "[REDACTED_CARD]", question)
    if not question:
        raise ValueError("Saisis une question pour lancer l’analyse.")
    if len(question) > MAX_QUESTION_CHARS:
        raise ValueError(f"La question ne doit pas dépasser {MAX_QUESTION_CHARS} caractères.")
    return question


def _integer(value: Any, default: int = 0, maximum: int = 10_000_000) -> int:
    if isinstance(value, bool):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return max(0, min(maximum, number))


def _risk(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return round(number, 4) if math.isfinite(number) and 0 <= number <= 1 else None


def _latency(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return round(min(60_000.0, max(0.0, number)), 2) if math.isfinite(number) else 0.0


def sanitize_context(value: Any) -> dict[str, Any]:
    """Keep only bounded counters and fixed labels; drop IPs, paths and payloads."""
    source = value if isinstance(value, dict) else {}
    totals_in = source.get("totals") if isinstance(source.get("totals"), dict) else {}
    totals = {
        key: _integer(totals_in.get(key))
        for key in ("events", "signals", "blocked", "allowed", "observed", "mlp_analyses")
    }
    recent: list[dict[str, Any]] = []
    events = source.get("recent") if isinstance(source.get("recent"), list) else []
    for event in events[:MAX_RECENT_EVENTS]:
        if not isinstance(event, dict):
            continue
        action = str(event.get("action", "")).upper()
        source_label = str(event.get("source", "")).lower()
        kind = str(event.get("type", ""))
        if not re.fullmatch(r"[A-Z0-9_-]{1,40}", kind):
            kind = "OTHER"
        timestamp = str(event.get("time", ""))
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?", timestamp):
            timestamp = "unknown"
        recent.append({
            "time": timestamp,
            "action": action if action in ALLOWED_ACTIONS else "OTHER",
            "type": kind,
            "source": source_label if source_label in ALLOWED_SOURCES else "other",
            "score": _integer(event.get("score"), maximum=100),
            "mlp_score": _risk(event.get("mlp_score")),
            "latency_ms": _latency(event.get("latency_ms", 0)),
        })

    return {
        "page": source.get("page") if isinstance(source.get("page"), str) and source.get("page") in ALLOWED_PAGES else "console",
        "period_days": max(1, min(30, _integer(source.get("period_days"), 7, 30))),
        "block_mode": bool(source.get("block_mode", False)),
        "mlp_available": bool(source.get("mlp_available", False)),
        "totals": totals,
        "recent": recent,
    }


def context_text(context: dict[str, Any]) -> str:
    return json.dumps(sanitize_context(context), ensure_ascii=False, separators=(",", ":"))


def clean_answer(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Le modèle n’a pas fourni de réponse textuelle.")
    answer = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value).strip()
    if not answer:
        raise ValueError("Le modèle n’a pas fourni de réponse.")
    return answer[:6000]
