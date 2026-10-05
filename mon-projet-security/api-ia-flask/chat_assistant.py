"""
Assistant chat du dashboard sécurité – logique côté Python.
Utilise la BDD MySQL (security_incidents) et les métriques du modèle pour répondre.
En aval des intentions : LLM optionnel (Gemini, Groq, OpenAI) pour questions libres.
"""
import os
import re
import json
from datetime import datetime
from typing import Any, Optional

# Connexion MySQL optionnelle (si MYSQL_* définis)
_db = None


def get_db():
    """Connexion MySQL (singleton). Retourne None si config absente."""
    global _db
    if _db is not None:
        return _db
    host = os.environ.get("MYSQL_HOST") or os.environ.get("DB_HOST", "127.0.0.1")
    user = os.environ.get("MYSQL_USER") or os.environ.get("DB_USERNAME", "root")
    password = os.environ.get("MYSQL_PASSWORD") or os.environ.get("DB_PASSWORD", "")
    database = os.environ.get("MYSQL_DATABASE") or os.environ.get("DB_DATABASE", "mon_projet_securite")
    port = int(os.environ.get("MYSQL_PORT") or os.environ.get("DB_PORT", "3306"))
    try:
        import pymysql
        _db = pymysql.connect(
            host=host,
            user=user,
            password=password,
            database=database,
            port=port,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )
    except Exception:
        _db = None
    return _db


def _query_one(conn, sql: str, args: tuple = ()) -> Optional[dict]:
    if not conn:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchone()
    except Exception:
        return None


def _query_all(conn, sql: str, args: tuple = ()) -> list:
    if not conn:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchall() or []
    except Exception:
        return []


def count_for_period(period: int, blocked_only: bool = False) -> int:
    interval = "24 HOUR" if period == 1 else f"{int(period)} DAY"
    and_blocked = " AND COALESCE(blocked, 0) = 1" if blocked_only else ""
    sql = (
        "SELECT COUNT(*) AS c FROM security_incidents "
        f"WHERE created_at >= DATE_SUB(NOW(), INTERVAL {interval}){and_blocked}"
    )
    row = _query_one(get_db(), sql)
    return int(row["c"]) if row and "c" in row else 0


def get_recent_attacks(limit: int = 5, period: int = 7) -> list:
    conn = get_db()
    if not conn:
        return []
    interval = "24 HOUR" if period == 1 else f"{int(period)} DAY"
    sql = (
        "SELECT threat_type, ip_address, payload_preview, created_at "
        "FROM security_incidents "
        f"WHERE created_at >= DATE_SUB(NOW(), INTERVAL {interval}) "
        "ORDER BY created_at DESC LIMIT %s"
    )
    rows = _query_all(conn, sql, (limit,))
    for r in rows:
        r["time_ago"] = _time_ago(r.get("created_at") or "")
        r["payload_preview"] = (r.get("payload_preview") or "")[:50]
    return rows


def _time_ago(ts: str) -> str:
    if not ts:
        return "-"
    try:
        t = datetime.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S")
        delta = datetime.now() - t
        days, sec = delta.days, delta.seconds
        if days > 0:
            return f"{days} jour(s)"
        if sec >= 3600:
            return f"{sec // 3600} heure(s)"
        if sec >= 60:
            return f"{sec // 60} minute(s)"
        return "À l'instant"
    except Exception:
        return "-"


def get_detection_breakdown(period_days: int = 7) -> dict:
    sql = (
        "SELECT detection_method, COUNT(*) AS c FROM security_incidents "
        f"WHERE created_at >= DATE_SUB(NOW(), INTERVAL {int(period_days)} DAY) "
        "GROUP BY detection_method"
    )
    rows = _query_all(get_db(), sql)
    out = {"WAF": 0, "AI": 0}
    for r in rows:
        method = (r.get("detection_method") or "").strip().upper()
        cnt = int(r.get("c") or 0)
        if method == "AI":
            out["AI"] = cnt
        else:
            out["WAF"] += cnt
    return out


def get_avg_confidence_24h() -> Optional[float]:
    sql = (
        "SELECT AVG(ai_confidence) AS avg_c FROM security_incidents "
        "WHERE DATE(created_at) = CURDATE() AND ai_confidence IS NOT NULL"
    )
    row = _query_one(get_db(), sql)
    if not row or row.get("avg_c") is None:
        return None
    return round(float(row["avg_c"]), 2)


def get_retrain_suggestion(training_date: Optional[str]) -> Optional[dict]:
    if not training_date or not training_date.strip():
        return None
    sql = "SELECT COUNT(*) AS c FROM security_incidents WHERE created_at > %s"
    row = _query_one(get_db(), sql, (training_date.strip() + " 00:00:00",))
    if not row:
        return None
    return {"count": int(row.get("c") or 0), "training_date": training_date.strip()}


def get_top_threat(period: int = 7) -> str:
    interval = "24 HOUR" if period == 1 else f"{int(period)} DAY"
    sql = (
        "SELECT threat_type, COUNT(*) AS count FROM security_incidents "
        f"WHERE created_at >= DATE_SUB(NOW(), INTERVAL {interval}) "
        "GROUP BY threat_type ORDER BY count DESC LIMIT 1"
    )
    row = _query_one(get_db(), sql)
    if not row:
        return "SQL Injection"
    return (row.get("threat_type") or "SQL Injection").strip() or "SQL Injection"


def get_peak_hour() -> str:
    sql = (
        "SELECT HOUR(created_at) AS hour FROM security_incidents "
        "WHERE DATE(created_at) = CURDATE() "
        "GROUP BY HOUR(created_at) ORDER BY COUNT(*) DESC LIMIT 1"
    )
    row = _query_one(get_db(), sql)
    h = int(row["hour"]) if row and row.get("hour") is not None else 13
    return f"{h:02d}:00-{h+1:02d}:00"


def calculate_daily_change() -> float:
    sql = (
        "SELECT "
        "(SELECT COUNT(*) FROM security_incidents WHERE DATE(created_at) = CURDATE()) AS today, "
        "(SELECT COUNT(*) FROM security_incidents WHERE DATE(created_at) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)) AS yesterday"
    )
    row = _query_one(get_db(), sql)
    if not row:
        return 0.0
    today = int(row.get("today") or 0)
    yesterday = int(row.get("yesterday") or 0)
    if yesterday <= 0:
        return 0.0
    return round(((today - yesterday) / yesterday) * 100, 2)


def get_vulnerable_endpoints(limit: int = 5) -> list:
    sql = (
        "SELECT endpoint FROM security_incidents "
        "WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) "
        "GROUP BY endpoint HAVING COUNT(*) > 3 ORDER BY COUNT(*) DESC LIMIT %s"
    )
    rows = _query_all(get_db(), sql, (limit,))
    return [r.get("endpoint") or "" for r in rows if r.get("endpoint")]


def generate_recommendations() -> list:
    recs = []
    try:
        total7 = count_for_period(7, blocked_only=False)
        endpoints = get_vulnerable_endpoints(5)
        top_threat = get_top_threat(7)
        if total7 > 20:
            recs.append(
                "Forte activité malveillante (7 j). Envisager un réentraînement du modèle avec les payloads récents (export_payloads_for_ml.py)."
            )
        if 5 < total7 <= 20:
            recs.append("Auditer les logs d'accès et vérifier les faux positifs éventuels.")
        if endpoints:
            recs.append("Endpoints les plus ciblés : " + ", ".join(endpoints[:3]) + ".")
        if "UNION" in top_threat.upper() or "SQL" in top_threat.upper():
            recs.append("Prédominance d'injections SQL — le modèle ML est adapté ; garder le modèle à jour.")
    except Exception:
        pass
    if not recs:
        recs = [
            "Consulter régulièrement le dashboard et les exports CSV.",
            "Mettre à jour les certificats SSL si applicable.",
        ]
    return recs[:5]


def _build_llm_context(
    period_total: int,
    period_blocked: int,
    block_rate: float,
    daily_change: float,
    top_threat: str,
    peak_display: str,
    waf_count: int,
    ai_count: int,
    training_date: str,
    precision: Any,
    recall: Any,
    retrain_count: int,
    retrain_date: str,
    avg_conf_display: str,
    recommendations: list,
    vulnerable_endpoints: list,
) -> str:
    """Contexte factuel pour le LLM (ne pas inventer de chiffres)."""
    lines = [
        f"7 derniers jours : {period_total} tentatives, {period_blocked} bloquées ({block_rate} %).",
        f"Tendance vs veille : {daily_change:+.0f} %. Heure de pointe : {peak_display}. Menace fréquente : {top_threat}.",
        f"Répartition blocages : WAF {waf_count}, IA {ai_count}.",
        f"Modèle : précision {precision if precision is not None else '—'}, recall {recall if recall is not None else '—'}, entraînement {training_date}. Confiance moyenne 24h : {avg_conf_display}.",
        f"Nouveaux incidents depuis entraînement : {retrain_count} (date {retrain_date}).",
    ]
    if recommendations:
        lines.append("Recommandations : " + " ; ".join(recommendations[:3]))
    if vulnerable_endpoints:
        lines.append("Endpoints ciblés : " + ", ".join(vulnerable_endpoints[:5]))
    return "\n".join(lines)


def _call_groq(message: str, system: str, context_block: str, history: list) -> Optional[str]:
    """Appel Groq (gratuit, rapide). API compatible OpenAI."""
    groq_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not groq_key:
        return None
    try:
        import openai
        client = openai.OpenAI(api_key=groq_key, base_url="https://api.groq.com/openai/v1")
        model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
        messages = [{"role": "system", "content": system + "\n\n" + context_block}]
        for h in history[-10:]:
            role = (h.get("role") or "user").strip().lower()
            messages.append({"role": role if role == "assistant" else "user", "content": (h.get("content") or "")[:2000]})
        messages.append({"role": "user", "content": message[:2000]})
        r = client.chat.completions.create(model=model, messages=messages, max_tokens=500, temperature=0.3)
        if r.choices and r.choices[0].message and getattr(r.choices[0].message, "content", None):
            text = (r.choices[0].message.content or "").strip()
            if text:
                print("[chat_assistant] Groq OK", flush=True)
                return text
    except Exception as e:
        print(f"[chat_assistant] Groq erreur: {e}", flush=True)
    return None


def _call_llm(message: str, context: str, history: Optional[list] = None) -> Optional[str]:
    """
    Appel LLM pour questions libres.
    Priorité par défaut : Gemini → Groq → OpenAI.
    Si CHAT_LLM_PROVIDER=groq (ou USE_GROQ_ONLY=1) : uniquement Groq.
    Env : ENABLE_LLM_CHAT=0 pour désactiver.
    """
    disabled = os.environ.get("ENABLE_LLM_CHAT", "").strip().lower() in ("0", "false", "no")
    if disabled:
        return None
    has_gemini = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    has_groq = bool(os.environ.get("GROQ_API_KEY", "").strip())
    has_openai = bool(os.environ.get("OPENAI_API_KEY", "").strip())
    if not has_gemini and not has_groq and not has_openai:
        return None
    # Utiliser uniquement Groq si demandé
    use_groq_only = (
        os.environ.get("CHAT_LLM_PROVIDER", "").strip().lower() == "groq"
        or os.environ.get("USE_GROQ_ONLY", "").strip().lower() in ("1", "true", "yes")
    )
    history = history or []
    system = (
        "Tu es l'assistant du dashboard sécurité d'une application web. Tu réponds en français, de façon concise et professionnelle. "
        "Tu ne dois jamais inventer de chiffres : utilise uniquement le contexte fourni ci-dessous. "
        "Si la question sort du cadre sécurité/dashboard, dis-le poliment et propose des sujets que tu maîtrises (blocages, WAF, IA, métriques, recommandations)."
    )
    context_block = "Contexte actuel du dashboard :\n" + context

    # Si Groq uniquement : ne pas appeler Gemini
    if use_groq_only and has_groq:
        reply = _call_groq(message, system, context_block, history)
        if reply:
            return reply
        return None

    # 1) Gemini (prioritaire) — si échec (quota, etc.) → fallback Groq
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if gemini_key and not use_groq_only:
        try:
            import urllib.request
            model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
            prompt = system + "\n\n" + context_block + "\n\n"
            for h in history[-10:]:
                role = (h.get("role") or "user").strip().lower()
                content = (h.get("content") or "")[:2000]
                prompt += f"({role}): {content}\n\n"
            prompt += f"(user): {message[:2000]}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"maxOutputTokens": 500, "temperature": 0.3},
            }
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-goog-api-key": gemini_key,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            candidates = data.get("candidates") or []
            if candidates and candidates[0].get("content", {}).get("parts"):
                text = candidates[0]["content"]["parts"][0].get("text", "") or ""
                if text.strip():
                    return text.strip()
        except Exception as e:
            # Quota épuisé ou erreur API → basculement vers Groq
            err_msg = str(e).lower()
            is_quota = (
                getattr(e, "code", None) == 429
                or "429" in err_msg
                or "quota" in err_msg
                or "resource" in err_msg
                or "exhausted" in err_msg
                or "rate" in err_msg
            )
            if is_quota:
                print("[chat_assistant] Gemini quota épuisée → tentative Groq", flush=True)
            else:
                print("[chat_assistant] Gemini erreur → tentative Groq", flush=True)
            if has_groq:
                reply = _call_groq(message, system, context_block, history)
                if reply:
                    return reply

    # 2) Groq (gratuit, rapide)
    if has_groq:
        reply = _call_groq(message, system, context_block, history)
        if reply:
            return reply

    # 3) OpenAI (fallback optionnel)
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if api_key:
        try:
            import openai
            client = openai.OpenAI(api_key=api_key)
            model = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")
            messages = [{"role": "system", "content": system + "\n\n" + context_block}]
            for h in history[-10:]:
                role = (h.get("role") or "user").strip().lower()
                if role == "assistant":
                    role = "assistant"
                else:
                    role = "user"
                messages.append({"role": role, "content": (h.get("content") or "")[:2000]})
            messages.append({"role": "user", "content": message[:2000]})
            r = client.chat.completions.create(model=model, messages=messages, max_tokens=500, temperature=0.3)
            if r.choices and len(r.choices) > 0 and r.choices[0].message and getattr(r.choices[0].message, "content", None):
                return (r.choices[0].message.content or "").strip()
        except Exception:
            pass
    return None


def chat_reply(
    message: str,
    model_metrics: Optional[dict] = None,
    history: Optional[list] = None,
) -> dict:
    """
    Répond à un message utilisateur (intentions + données BDD / métriques).
    Retourne {"ok": bool, "reply": str}.
    """
    model_metrics = model_metrics or {}
    msg = (message or "").strip().lower()
    if not msg:
        return {
            "ok": True,
            "reply": "Posez une question sur le dashboard : blocages, métriques, WAF vs IA, recommandations, réentraînement…",
        }

    # Données (lecture BDD si dispo)
    db = get_db()
    period_total = count_for_period(7, False) if db else 0
    period_blocked = count_for_period(7, True) if db else 0
    block_rate = round((period_blocked / period_total) * 100, 1) if period_total else 100.0
    daily_change = calculate_daily_change() if db else 0.0
    top_threat = get_top_threat(7) if db else "—"
    peak_display = get_peak_hour() if db else "—"
    breakdown = get_detection_breakdown(7) if db else {"WAF": 0, "AI": 0}
    waf_count = int(breakdown.get("WAF") or 0)
    ai_count = int(breakdown.get("AI") or 0)
    training_date = (model_metrics.get("training_date") or "2026-01-15") if isinstance(model_metrics.get("training_date"), str) else "—"
    precision = model_metrics.get("precision")
    recall = model_metrics.get("recall")
    if precision is not None:
        precision = round(float(precision) * 100, 1)
    if recall is not None:
        recall = round(float(recall) * 100, 1)
    retrain = get_retrain_suggestion(training_date) if db and training_date != "—" else None
    retrain_count = int(retrain["count"]) if retrain else 0
    retrain_date = (retrain.get("training_date") or training_date) if retrain else training_date
    avg_conf = get_avg_confidence_24h() if db else None
    avg_conf_display = f"{avg_conf:.2f}" if avg_conf is not None else "—"
    recommendations = generate_recommendations() if db else []
    vulnerable_endpoints = get_vulnerable_endpoints(5) if db else []

    # Intentions (ordre prioritaire)
    # 1) 5 dernières attaques
    if re.search(
        r"\b(5\s*dernières?|dernières?\s*5|liste\s*des?\s*attaques|dernières?\s*attaques|quelles?\s*attaques?|attaques?\s*dont|victime)\b",
        msg,
        re.I,
    ):
        last5 = get_recent_attacks(5, 7)
        if not last5:
            return {"ok": True, "reply": "Aucune attaque enregistrée sur les 7 derniers jours."}
        lines = []
        for i, a in enumerate(last5, 1):
            typ = a.get("threat_type") or "SQL Injection"
            time_ago = a.get("time_ago") or "-"
            ip = a.get("ip_address") or ""
            payload = (a.get("payload_preview") or "")[:50]
            payload_s = f" — {payload}" if payload else ""
            lines.append(f"{i}. {typ} · {time_ago} · IP {ip}{payload_s}")
        return {"ok": True, "reply": "Les 5 dernières attaques :\n\n" + "\n\n".join(lines)}

    # 2) Résumé / blocages / statistiques (sans capturer "attaques" seul pour laisser les questions ouvertes au LLM)
    if re.search(
        r"\b(résumé|resume|resumer|blocage[s]?|bloqué[s]?|tentatives?|incidents?|aujourd['\u2019]hui|24\s*h|24h|ce\s*jour|du\s*jour|statistiques?|situation|état|nombre\s*de|combien\s*de)\b",
        msg,
        re.I | re.U,
    ):
        reply = f"Sur les 7 derniers jours : **{period_total}** tentative(s) dont **{period_blocked}** bloquée(s) ({block_rate} %). "
        if daily_change != 0.0:
            sign = "+" if daily_change > 0 else ""
            reply += f"Tendance : {sign}{daily_change:.0f} % par rapport à la veille. "
        reply += f"Heure de pointe : {peak_display}. Menace la plus fréquente : {top_threat}."
        return {"ok": True, "reply": reply}

    # 3) WAF vs IA
    if re.search(
        r"\b(waf|ia|ai|répartition|réparti|part\s*waf|part\s*ia|règles?\s*waf|intelligence\s*artificielle|qui\s*bloque)\b",
        msg,
        re.I,
    ):
        total_det = waf_count + ai_count
        reply = f"Répartition des blocages (7 jours) : **WAF** {waf_count}, **IA** {ai_count}."
        if total_det > 0:
            pct_waf = round((waf_count / total_det) * 100)
            pct_ai = round((ai_count / total_det) * 100)
            reply += f" Soit {pct_waf} % par règles WAF et {pct_ai} % par le modèle IA."
        return {"ok": True, "reply": reply}

    # 4) Métriques
    if re.search(
        r"\b(métrique[s]?|précision|recall|f1|accuracy|modèle|performance|score|statistiques?\s*modèle|qualité\s*du\s*modèle)\b",
        msg,
        re.I,
    ):
        prec_s = f"{precision} %" if precision is not None else "—"
        rec_s = f"{recall} %" if recall is not None else "—"
        reply = f"Métriques du modèle : précision {prec_s}, recall {rec_s}, date d'entraînement {training_date}. Confiance moyenne IA (24 h) : {avg_conf_display}."
        return {"ok": True, "reply": reply}

    # 5) Réentraînement
    if re.search(
        r"\b(réentrain|réentraînement|retrain|entrainement|mise\s*à\s*jour\s*du\s*modèle|réentraîner|entraîner\s*à\s*nouveau)\b",
        msg,
        re.I,
    ):
        if retrain_count > 0:
            reply = f"{retrain_count} nouvel(s) incident(s) depuis le dernier entraînement ({retrain_date}). Il est recommandé d'exporter les payloads (export_payloads_for_ml.py) puis de lancer train_model.py pour mettre à jour le modèle."
        else:
            reply = f"Pas de nouvel incident depuis l'entraînement ({retrain_date}). Aucun réentraînement urgent nécessaire."
        return {"ok": True, "reply": reply}

    # 6) Recommandations
    if re.search(
        r"\b(recommandation[s]?|conseil[s]?|action[s]?|que\s*faire|suggère|suggestion[s]?|priorité|priorités)\b",
        msg,
        re.I,
    ):
        if not recommendations:
            return {"ok": True, "reply": "Aucune recommandation spécifique pour le moment. Surveillez les attaques et les métriques du modèle."}
        return {"ok": True, "reply": "Recommandations : " + " ".join(recommendations[:3])}

    # 7) Endpoints vulnérables
    if re.search(
        r"\b(endpoint[s]?|vulnérable[s]?|ciblé[s]?|cibles?|url[s]?\s*attaqué|pages?\s*visé)\b",
        msg,
        re.I,
    ):
        if not vulnerable_endpoints:
            return {"ok": True, "reply": "Aucun endpoint particulièrement ciblé identifié sur la période."}
        return {"ok": True, "reply": "Endpoints les plus ciblés : " + ", ".join(vulnerable_endpoints[:5]) + "."}

    # 8) Salut / aide
    if re.search(r"\b(hello|bonjour|salut|aide|help|ça\s*va|coucou|tu\s*peux\s*m['\u2019]aider)\b", msg, re.I | re.U):
        return {
            "ok": True,
            "reply": "Bonjour. Je peux vous renseigner sur les blocages, la répartition WAF/IA, les métriques du modèle, le réentraînement et les recommandations. Posez une question courte.",
        }

    # 9) Explique / top pays / sections dashboard
    if re.search(r"\b(explique|expliquer|top\s*pays|pays|géolocalisation|origines?|d['\u2019]où)\b", msg, re.I | re.U):
        reply = (
            "**Sections du dashboard :**\n\n"
            "• **Top Pays** : affiche les pays d'origine des adresses IP des attaques détectées.\n"
            "• **Blocages** : nombre de tentatives bloquées par le WAF et l'IA.\n"
            "• **WAF vs IA** : répartition entre règles WAF et modèle IA.\n"
            "• **Métriques** : précision, recall du modèle de détection.\n"
            "• **Recommandations** : actions suggérées selon l'activité."
        )
        return {"ok": True, "reply": reply}

    # 10) Rapport / résumé / "fait moi un rapport"
    if re.search(r"\b(rapport|résume|resume|résumer|fait\s*moi|donne\s*moi|donne\s*-moi|résumé|summary)\b", msg, re.I | re.U):
        rec_str = (" " + " ; ".join(recommendations[:2])) if recommendations else ""
        reply = (
            f"**Rapport sécurité (7 jours)**\n\n"
            f"• Tentatives : **{period_total}** dont **{period_blocked}** bloquées ({block_rate} %)\n"
            f"• Tendance : {daily_change:+.0f} % vs veille\n"
            f"• Répartition : WAF {waf_count}, IA {ai_count}\n"
            f"• Menace dominante : {top_threat}\n"
            f"• Heure de pointe : {peak_display}\n"
            f"• Métriques : précision {precision if precision is not None else '—'}, recall {recall if recall is not None else '—'}{rec_str}"
        )
        return {"ok": True, "reply": reply}

    # Aucune intention reconnue : essai LLM (Gemini, Groq, OpenAI) avec contexte dashboard
    fallback = (
        "Je n'ai pas reconnu votre question.\n\n"
        "**À essayer :** « 5 dernières attaques », « Combien de blocages ? », « WAF vs IA », « Métriques du modèle », "
        "« Recommandations », « Réentraînement », « Fait moi un rapport », « Explique top pays ».\n\n"
        "_Pour les questions libres : GEMINI_API_KEY ou GROQ_API_KEY dans .env_"
    )
    context = _build_llm_context(
        period_total, period_blocked, block_rate, daily_change, top_threat, peak_display,
        waf_count, ai_count, training_date, precision, recall, retrain_count, retrain_date,
        avg_conf_display, recommendations, vulnerable_endpoints,
    )
    llm_reply = _call_llm((message or "").strip(), context, history)
    if llm_reply:
        return {"ok": True, "reply": llm_reply}
    return {"ok": True, "reply": fallback}
