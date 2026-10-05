"""
Module IA Flask - Analyse des menaces SQL Injection (ML entraîné)
Aligné avec l'architecture : Middleware Sécurité (PHP) -> API IA (Flask) -> Résultat
POST /analyze : extraction de features + modèle ML (MLP) ou fallback règles
"""
import os

# Charger .env du dossier api-ia-flask (config MySQL pour le chat, optionnel)
def _load_env():
    try:
        import importlib.util
        spec = importlib.util.find_spec("dotenv")
        if spec is not None and spec.origin is not None:
            dotenv = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(dotenv)  # type: ignore[union-attr]
            dotenv.load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    except Exception:
        pass
_load_env()

import time
import joblib
import numpy as np
from flask import Flask, request, jsonify

from features import FEATURE_NAMES, extract_features_dict, features_to_vector
from chat_assistant import chat_reply

app = Flask(__name__)
MODEL_VERSION = "2026.2.0-ml"
RISK_THRESHOLD = 0.75

CONTEXT_WEIGHTS = {
    "login": 1.3,
    "registration": 1.2,
    "search": 1.1,
    "admin": 1.5,
    "admin_panel": 1.4,
    "api": 1.25,
    "file_upload": 1.35,
    "default": 1.0,
}

# Chargement du modèle ML entraîné (si présent)
ML_MODEL = None
_model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.joblib")
if os.path.isfile(_model_path):
    try:
        ML_MODEL = joblib.load(_model_path)
    except Exception:
        ML_MODEL = None


def _calculate_risk_fallback(features: dict, context_weight: float):
    """Fallback règles si modèle ML non chargé."""
    risk = 0.1
    risk_factors = {
        "has_union_pattern": 0.35,
        "has_tautology": 0.25,
        "has_time_based": 0.30,
        "has_comment": 0.20,
        "special_char_ratio": 0.15,
        "entropy": 0.20,
        "sql_keywords": 0.10,
    }
    for key, weight in risk_factors.items():
        val = features.get(key, 0)
        if isinstance(val, (int, float)):
            risk += weight * min(max(val, 0), 1.0) if val else 0
        elif key == "special_char_ratio" and val > 0.3:
            risk += weight
        elif key == "entropy" and val > 4.0:
            risk += weight * min((val - 4) / 4, 1.0)
    if features.get("length", 0) > 200:
        risk += 0.15
    if features.get("keyword_density", 0) > 0.3:
        risk += 0.25
    risk = min(risk * context_weight, 1.0)
    confidence = min(0.95, 0.5 + (risk * 0.5))
    return round(risk, 3), round(confidence, 3)


def classify_threat(features: dict) -> str:
    if features.get("has_time_based"):
        return "TIME_BASED_SQLi"
    if features.get("has_error_based"):
        return "ERROR_BASED_INJECTION"
    if features.get("has_union_pattern"):
        return "UNION_SQLi"
    if features.get("has_tautology"):
        return "BOOLEAN_BASED_INJECTION"
    if features.get("has_comment"):
        return "COMMENT_INJECTION"
    if features.get("special_char_ratio", 0) > 0.4:
        return "SUSPICIOUS_INPUT"
    if features.get("sql_keywords", 0) > 2:
        return "SQL_KEYWORDS_DETECTED"
    return "UNCLASSIFIED_THREAT"


@app.route("/analyze", methods=["POST"])
def analyze():
    start = time.perf_counter()
    data = request.get_json(force=True, silent=True) or {}
    input_str = data.get("input", data.get("payload", ""))
    context = data.get("context", {})
    context_type = context.get("type", "default")
    context_weight = CONTEXT_WEIGHTS.get(context_type, 1.0)

    if not input_str:
        return jsonify({
            "risk": 0.0,
            "confidence": 0.0,
            "type": "NONE",
            "model_version": MODEL_VERSION,
            "processing_time_ms": 0,
            "error": "missing input",
        }), 400

    features = extract_features_dict(input_str)
    threat_type = classify_threat(features)

    risk_factors = []
    if ML_MODEL is not None:
        # Prédiction par le modèle ML entraîné (MLP)
        model = ML_MODEL["model"]
        vector = np.array([features_to_vector(features)], dtype=np.float64)
        proba = model.predict_proba(vector)[0]
        risk = float(proba[1])  # proba classe 1 (SQLi)
        risk = min(risk * context_weight, 1.0)
        confidence = min(0.95, 0.5 + (risk * 0.5))
        risk = round(risk, 3)
        confidence = round(confidence, 3)
        ml_used = True
        # Explicabilité : top 5 facteurs contributifs (importance * valeur)
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
            vec = vector[0]
            contrib = [
                (FEATURE_NAMES[i], float(vec[i]), float(importances[i]) * (1.0 + abs(vec[i])))
                for i in range(min(len(FEATURE_NAMES), len(importances), len(vec)))
            ]
            contrib.sort(key=lambda x: -x[2])
            risk_factors = [
                {"name": n, "value": v, "contribution": round(c, 4)}
                for n, v, c in contrib[:5]
            ]
    else:
        risk, confidence = _calculate_risk_fallback(features, context_weight)
        ml_used = False

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

    out = {
        "risk": risk,
        "confidence": confidence,
        "type": threat_type,
        "model_version": MODEL_VERSION,
        "processing_time_ms": elapsed_ms,
        "request_id": data.get("request_id"),
        "ml_used": ml_used,
        "features": {k: v for k, v in features.items() if k in ("length", "sql_keywords", "has_union_pattern", "has_tautology", "has_time_based")},
    }
    if risk_factors:
        out["risk_factors"] = risk_factors
    return jsonify(out)


@app.route("/", methods=["GET"])
def index():
    """Page d'accueil affichée dans le navigateur pour confirmer que l'API est en marche."""
    html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API IA - Module SQL Injection</title>
    <style>
        body {{ font-family: system-ui, sans-serif; max-width: 600px; margin: 2rem auto; padding: 1rem; background: #0f172a; color: #f1f5f9; }}
        h1 {{ color: #38bdf8; font-size: 1.5rem; }}
        .status {{ background: #065f46; color: #6ee7b7; padding: 0.5rem 1rem; border-radius: 8px; display: inline-block; margin: 1rem 0; }}
        ul {{ color: #94a3b8; line-height: 1.8; }}
        code {{ background: #1e293b; padding: 0.2rem 0.4rem; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>API IA – Module SQL Injection</h1>
    <p class="status">✓ En marche</p>
    <p>Version du modèle : <strong>{MODEL_VERSION}</strong></p>
    <p>ML entraîné : <strong>{"Oui (MLP)" if ML_MODEL else "Non (règles)"}</strong></p>
    <p>Endpoints :</p>
    <ul>
        <li><code>POST /analyze</code> – Analyse d'une entrée (risk, confidence, type)</li>
        <li><code>POST /chat</code> – Assistant chat (Gemini → Groq)</li>
        <li><code>GET /health</code> – Contrôle de disponibilité</li>
        <li><code>GET /ping</code> – Test rapide</li>
        <li><code>GET /debug-gemini</code> – Config LLM (Gemini, Groq, OpenAI)</li>
    </ul>
    <p style="margin-top: 2rem; font-size: 0.9rem; color: #64748b;">Middleware PHP → appelle cette API pour l'analyse IA.</p>
</body>
</html>
"""
    return html


def _load_metrics():
    """Charge les métriques sauvegardées à l'entraînement (metrics.json)."""
    import json
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metrics.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


@app.route("/metrics", methods=["GET"])
def metrics():
    """Métriques du modèle (precision, recall, f1) issues de l'entraînement."""
    data = _load_metrics() or {}
    data["model_version"] = MODEL_VERSION
    data["ml_loaded"] = ML_MODEL is not None
    return jsonify(data)


@app.route("/ping", methods=["GET"])
def ping():
    """Test rapide de disponibilité."""
    return jsonify({"status": "ok", "message": "pong"})


@app.route("/debug-gemini", methods=["GET"])
def debug_gemini():
    """Test configuration LLM (Gemini, Groq, OpenAI)."""
    has_gemini = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    has_groq = bool(os.environ.get("GROQ_API_KEY", "").strip())
    has_openai = bool(os.environ.get("OPENAI_API_KEY", "").strip())
    llm_disabled = os.environ.get("ENABLE_LLM_CHAT", "").strip().lower() in ("0", "false", "no")
    return jsonify({
        "status": "ok",
        "gemini_configured": has_gemini,
        "groq_configured": has_groq,
        "openai_configured": has_openai,
        "llm_chat_enabled": not llm_disabled,
        "priority": "Gemini → Groq → OpenAI",
    })


@app.route("/health", methods=["GET"])
def health():
    has_gemini = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    has_groq = bool(os.environ.get("GROQ_API_KEY", "").strip())
    has_openai = bool(os.environ.get("OPENAI_API_KEY", "").strip())
    llm_disabled = os.environ.get("ENABLE_LLM_CHAT", "").strip().lower() in ("0", "false", "no")
    data = {
        "status": "ok",
        "model_version": MODEL_VERSION,
        "ml_loaded": ML_MODEL is not None,
        "llm_chat_available": (has_gemini or has_groq or has_openai) and not llm_disabled,
    }
    # En navigateur : afficher une page lisible au lieu du JSON brut
    accept = request.headers.get("Accept", "")
    if "text/html" in accept and "application/json" not in accept:
        ml_status = "Oui (RandomForest)" if data["ml_loaded"] else "Non (règles)"
        llm_status = "Oui (Gemini → Groq)" if data["llm_chat_available"] else "Non (définir GEMINI_API_KEY ou GROQ_API_KEY dans .env)"
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Health - API IA</title>
    <style>
        body {{ font-family: system-ui, sans-serif; max-width: 500px; margin: 3rem auto; padding: 2rem; background: #0f172a; color: #e2e8f0; }}
        h1 {{ color: #38bdf8; font-size: 1.5rem; margin-bottom: 1rem; }}
        .ok {{ color: #4ade80; }}
        .row {{ margin: 0.5rem 0; }}
        code {{ background: #1e293b; padding: 0.2rem 0.5rem; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>API IA – État</h1>
    <p class="row"><span class="ok">✓</span> Status : <strong>{data["status"]}</strong></p>
    <p class="row">Version : <code>{data["model_version"]}</code></p>
    <p class="row">ML chargé : <strong>{ml_status}</strong></p>
    <p class="row">Chat LLM (questions libres) : <strong>{llm_status}</strong></p>
    <p style="margin-top: 2rem; font-size: 0.9rem; color: #94a3b8;">POST /analyze pour l’analyse. <a href="/" style="color: #38bdf8;">Accueil</a></p>
</body>
</html>"""
        return html
    return jsonify(data)


@app.route("/chat", methods=["POST"])
def chat():
    """Assistant chat du dashboard : logique intelligence côté Python (+ LLM optionnel, historique)."""
    data = request.get_json(force=True, silent=True) or {}
    message = (data.get("message") or "").strip() if isinstance(data.get("message"), str) else ""
    history = data.get("history")
    if not isinstance(history, list):
        history = None
    metrics = _load_metrics() or {}
    result = chat_reply(message, model_metrics=metrics, history=history)
    return jsonify(result)


def _startup_llm_check():
    """Vérifie la config LLM (Gemini, Groq) au démarrage."""
    has_gemini = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    has_groq = bool(os.environ.get("GROQ_API_KEY", "").strip())
    print("API IA Flask - Démarrage sur http://127.0.0.1:5000", flush=True)
    print(f"  Gemini: {'✓ configuré' if has_gemini else '— non configuré'}", flush=True)
    print(f"  Groq: {'✓ configuré' if has_groq else '— non configuré'}", flush=True)
    print("  Tester : GET /ping ou GET /debug-gemini", flush=True)


if __name__ == "__main__":
    _startup_llm_check()
    app.run(host="127.0.0.1", port=5000, debug=False)
