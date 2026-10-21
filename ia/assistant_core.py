"""Input and context boundaries for the local CyberShield LLM assistant."""

from __future__ import annotations

import json
import math
import re
import unicodedata
from typing import Any

MAX_QUESTION_CHARS = 1200
MAX_RECENT_EVENTS = 8
ALLOWED_ACTIONS = {"BLOCKED", "BLOCKED_BY_AI", "ALLOWED", "MONITORED"}
ALLOWED_SOURCES = {"heuristic", "ai", "mlp", "ip_policy"}
ALLOWED_PAGES = {"dashboard", "lab", "ip-rules", "assistant"}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}


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


def _selected_event(value: Any) -> dict[str, Any] | None:
    """Allow only bounded rule metadata; event payloads and operator notes never pass through."""
    if not isinstance(value, dict):
        return None
    rule_id = str(value.get("rule_id", ""))
    if not re.fullmatch(r"CS-[A-Z0-9-]{3,24}", rule_id):
        return None
    action = str(value.get("action", "")).upper()
    source = str(value.get("source", "")).lower()
    kind = str(value.get("type", ""))
    timestamp = str(value.get("time", ""))
    cwe = str(value.get("cwe", ""))
    owasp = str(value.get("owasp", ""))
    return {
        "rule_id": rule_id,
        "rule_name": re.sub(r"[\x00-\x1f\x7f]", " ", str(value.get("rule_name", "")))[:100],
        "severity": value.get("severity") if value.get("severity") in ALLOWED_SEVERITIES else "medium",
        "category": re.sub(r"[\x00-\x1f\x7f]", " ", str(value.get("category", "")))[:80],
        "cwe": cwe if re.fullmatch(r"CWE-[0-9]{1,5}", cwe) else "",
        "owasp": owasp if re.fullmatch(r"A[0-9]{2}:2021-[A-Za-z -]{1,40}", owasp) else "",
        "description": re.sub(r"[\x00-\x1f\x7f]", " ", str(value.get("description", "")))[:500],
        "remediation": re.sub(r"[\x00-\x1f\x7f]", " ", str(value.get("remediation", "")))[:500],
        "action": action if action in ALLOWED_ACTIONS else "OTHER",
        "type": kind if re.fullmatch(r"[A-Z0-9_-]{1,40}", kind) else "OTHER",
        "source": source if source in ALLOWED_SOURCES else "other",
        "score": _integer(value.get("score"), maximum=100),
        "mlp_score": _risk(value.get("mlp_score")),
        "time": timestamp[:25] if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?", timestamp) else "unknown",
    }


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

    result = {
        "page": source.get("page") if isinstance(source.get("page"), str) and source.get("page") in ALLOWED_PAGES else "console",
        "period_days": max(1, min(30, _integer(source.get("period_days"), 7, 30))),
        "block_mode": bool(source.get("block_mode", False)),
        "mlp_available": bool(source.get("mlp_available", False)),
        "totals": totals,
        "recent": recent,
    }
    selected = _selected_event(source.get("selected_event"))
    if selected is not None:
        result["selected_event"] = selected
    return result


def context_text(context: dict[str, Any]) -> str:
    return json.dumps(sanitize_context(context), ensure_ascii=False, separators=(",", ":"))


def model_context_text(context: dict[str, Any]) -> str:
    """Compact only the allowed recent sample; global counters retain their scope."""
    safe = sanitize_context(context)
    recent = safe.pop("recent")
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for event in recent:
        key = (event["type"], event["action"], event["source"])
        if key not in groups:
            groups[key] = {"type": key[0], "action": key[1], "source": key[2], "count": 0, "score_max": 0}
        group = groups[key]
        group["count"] += 1
        group["score_max"] = max(group["score_max"], event["score"])
    safe["recent_sample"] = {
        "scope": "up_to_8_recent_events_only", "size": len(recent), "groups": list(groups.values()),
    }
    return json.dumps(safe, ensure_ascii=False, separators=(",", ":"))


def clean_answer(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Le modèle n’a pas fourni de réponse textuelle.")
    answer = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value).strip()
    if not answer:
        raise ValueError("Le modèle n’a pas fourni de réponse.")
    answer = re.sub(r"\b(authorization|cookie|set-cookie)\s*:\s*[^\r\n]*", r"\1: [REDACTED]", answer, flags=re.I)
    answer = re.sub(r"\b(password|passwd|pwd|token|secret|api[_-]?key|csrf[_-]?token|totp|otp)\s*([:=])\s*(?:\"[^\"]*\"|'[^']*'|[^&\s,;]+)", r"\1\2[REDACTED]", answer, flags=re.I)
    answer = re.sub(r"\b(?:\d[ -]?){13,19}\b", "[REDACTED_CARD]", answer)
    return answer[:6000]


def local_answer(question: str, context: dict[str, Any]) -> tuple[str, str] | None:
    """Answer only explicit, bounded intents from sanitized facts, without a model."""
    normalized = unicodedata.normalize("NFKD", question.lower())
    normalized = "".join(char for char in normalized if not unicodedata.combining(char))
    normalized = re.sub(r"[^a-z0-9]+", " ", normalized).strip()
    safe = sanitize_context(context)
    if normalized in {"salut", "bonjour", "bonsoir", "hello", "coucou", "salut cybershield", "bonjour cybershield"}:
        return "greeting", "Bonjour ! Je peux présenter le bilan de la supervision, expliquer le mode de protection ou une alerte sélectionnée. Que souhaites-tu examiner ?"
    if normalized in {"aide", "help", "que peux tu faire", "que sais tu faire", "tes capacites", "comment peux tu m aider", "comment utiliser l assistant"}:
        return "help", "Je peux lire les compteurs de supervision, expliquer le mode observation ou blocage et les métadonnées d’une alerte sélectionnée. Ces réponses sont calculées localement. Pour une autre question défensive, le modèle local peut proposer une explication. Je ne peux modifier aucun réglage ni exécuter d’action."
    if normalized in {
        "bilan", "resume", "compteurs", "statistiques", "bilan de la supervision", "resume de la supervision",
        "fais le bilan", "fais le bilan de la supervision", "resume la supervision", "resume les donnees",
        "quel est le bilan", "quels sont les compteurs", "quels sont les compteurs de supervision",
        "combien de requetes sont bloquees", "combien de requetes ont ete bloquees", "combien d evenements",
        "qu est ce que tu pourrais me dire aujourd hui sur les donnees",
    }:
        totals = safe["totals"]
        count = lambda key: f"{totals[key]:,}".replace(",", " ")
        return "summary", (
            f"Sur les {safe['period_days']} derniers jours, le contexte transmis contient {count('events')} événements consignés : "
            f"{count('blocked')} bloqués, {count('observed')} observés et {count('allowed')} autorisés. "
            f"{count('signals')} signaux sont à examiner et {count('mlp_analyses')} analyses MLP ont été journalisées. "
            "Ces compteurs décrivent les traces disponibles ; ils ne prouvent pas à eux seuls une compromission."
        )
    if normalized in {
        "que signifie le mode observation", "explique le mode observation", "qu est ce que le mode observation",
    }:
        return "mode_definition", "Le mode observation consigne les signaux SQLi sans interrompre les requêtes au titre de ces signaux. Les contrôles d’accès IP, de débit et de taille restent distincts. Cette définition ne confirme pas le mode actuellement configuré : demande « Quel est le mode de protection ? » pour lire l’état transmis par la console."
    if normalized in {
        "mode", "mode de protection", "etat du filtre", "quel est le mode", "quel est le mode de protection",
        "quel est le mode du filtre", "quel est l etat du filtre", "explique le mode de protection",
        "le blocage est il actif", "le filtre bloque t il les requetes", "sommes nous en mode observation",
    }:
        if safe["block_mode"]:
            message = "Le blocage SQLi est activé dans la configuration transmise. Les règles et le MLP portent les décisions du filtre."
        else:
            message = "Le filtre SQLi est en mode observation : les signaux sont consignés sans interrompre la requête au titre du SQLi. Les règles d’accès IP et les limites de débit et de taille restent distinctes."
        mlp = "Le service MLP est déclaré disponible." if safe["mlp_available"] else "Le service MLP n’est pas déclaré disponible."
        return "mode", f"{message} {mlp} L’assistant reste en lecture seule."
    if normalized in {
        "explique cette alerte", "explique l alerte", "explique l alerte selectionnee", "que signifie cette alerte",
        "que signifie l alerte selectionnee", "explique cet evenement", "explique la regle selectionnee",
        "explique cette alerte sa regle et les mesures de correction recommandees",
    }:
        selected = safe.get("selected_event")
        if not selected:
            return "selected_event", "Aucune alerte sélectionnée n’est fournie. Ouvre les détails d’un événement dans la supervision, puis choisis l’aide de l’assistant pour cet événement."
        labels = {"BLOCKED": "bloquée", "BLOCKED_BY_AI": "bloquée par le filtre avec le MLP", "MONITORED": "observée", "ALLOWED": "autorisée"}
        decision = labels.get(selected["action"], "non renseignée")
        rule = selected["rule_name"] or selected["rule_id"]
        explanation = selected["description"] or "Un signal correspondant à cette règle a été journalisé."
        remediation = selected["remediation"] or "Vérifie la trace et les requêtes préparées de l’application."
        return "selected_event", (
            f"Règle {selected['rule_id']} — {rule}. Décision enregistrée : {decision}. "
            f"{explanation} Recommandation de la règle : {remediation} "
            "Il s’agit d’un signal, pas d’une preuve de compromission. Le score MLP éventuel n’est pas une probabilité calibrée."
        )
    return None
