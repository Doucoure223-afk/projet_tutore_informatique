"""CyberShield local MLP service. Never executes or logs submitted SQL."""

import argparse
from collections import deque
import math
from pathlib import Path
import threading
import time

import joblib
import numpy as np
import sklearn
from flask import Flask, jsonify, request
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from werkzeug.exceptions import HTTPException

from features import FEATURE_NAMES, FEATURE_SCHEMA, MAX_SQL_LENGTH, attack_type, extract_features

BASE = Path(__file__).resolve().parent
MAX_BODY_BYTES = 32768


class SlidingWindowLimiter:
    def __init__(self, limit=120, window=60.0, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self.requests = {}
        self.lock = threading.Lock()

    def allow(self, key):
        now = self.clock()
        with self.lock:
            # Bound storage even if called behind an unexpected local proxy.
            for previous in list(self.requests):
                if not self.requests[previous] or self.requests[previous][-1] <= now - self.window:
                    del self.requests[previous]
            if key not in self.requests and len(self.requests) >= 1024:
                return False, math.ceil(self.window)
            times = self.requests.setdefault(key, deque())
            while times and times[0] <= now - self.window:
                times.popleft()
            if len(times) >= self.limit:
                return False, max(1, math.ceil(self.window - (now - times[0])))
            times.append(now)
            return True, 0


def load_model(path):
    # Joblib uses pickle: load only this locally generated, administrator-owned file.
    artifact = joblib.load(path)
    if not isinstance(artifact, dict):
        raise ValueError("Invalid model artifact")
    if artifact.get("feature_schema") != FEATURE_SCHEMA or artifact.get("feature_names") != list(FEATURE_NAMES):
        raise ValueError("Incompatible feature schema")
    if artifact.get("sklearn_version") != sklearn.__version__:
        raise ValueError("Train again with the installed scikit-learn version")
    classifier, scaler = artifact.get("classifier"), artifact.get("scaler")
    if not isinstance(classifier, MLPClassifier) or not isinstance(scaler, StandardScaler):
        raise ValueError("Unexpected model or scaler")
    if tuple(classifier.hidden_layer_sizes) != (128, 64, 32) or classifier.activation != "relu":
        raise ValueError("Unexpected MLP architecture")
    if classifier.n_features_in_ != len(FEATURE_NAMES) or list(classifier.classes_) != [0, 1]:
        raise ValueError("Unexpected input or output dimensions")
    if artifact.get("threshold") != 0.75 or not artifact.get("model_version"):
        raise ValueError("Missing version or incorrect decision threshold")
    probe = classifier.predict_proba(scaler.transform(np.zeros((1, len(FEATURE_NAMES)))))
    if not np.isfinite(probe).all():
        raise ValueError("Model returned a non-finite probability")
    return artifact


def create_app(model_path=BASE / "models" / "model.joblib", rate_limit=120):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=MAX_BODY_BYTES, JSON_SORT_KEYS=False)
    limiter = SlidingWindowLimiter(limit=rate_limit)
    try:
        artifact = load_model(Path(model_path))
    except Exception as exc:
        app.logger.warning("MLP unavailable (%s); run ia/train.py then restart.", type(exc).__name__)
        artifact = None
    app.extensions["cybershield_model"] = artifact
    app.extensions["cybershield_limiter"] = limiter

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error=exc.name, status="error"), exc.code

    @app.get("/health")
    def health():
        return jsonify(status="ok" if artifact else "model_unavailable", model_loaded=artifact is not None,
                       model_version=artifact["model_version"] if artifact else None,
                       version=artifact["model_version"] if artifact else None,
                       analysis_method="MLP", dataset_source=artifact["dataset_source"] if artifact else None,
                       threshold=0.75), 200 if artifact else 503

    @app.post("/analyse")
    def analyse():
        allowed, retry_after = limiter.allow(request.remote_addr or "unknown")
        if not allowed:
            response = jsonify(error="rate_limit_exceeded", status="error")
            response.headers["Retry-After"] = str(retry_after)
            return response, 429
        if not request.is_json:
            return jsonify(error="Content-Type must be application/json", status="error"), 415
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="A JSON object is required", status="error"), 400
        sql, context = body.get("sql"), body.get("context", "unknown")
        if not isinstance(sql, str) or len(sql) > MAX_SQL_LENGTH:
            return jsonify(error="sql must be a string of at most 8192 characters", status="error"), 400
        if not isinstance(context, str) or len(context) > 64:
            return jsonify(error="context must be a string of at most 64 characters", status="error"), 400
        if artifact is None:
            return jsonify(error="model_unavailable", status="error", model_loaded=False), 503
        features = extract_features(sql)
        vector = np.asarray([[features[name] for name in FEATURE_NAMES]], dtype=float)
        risk = float(artifact["classifier"].predict_proba(artifact["scaler"].transform(vector))[0, 1])
        if not math.isfinite(risk):
            return jsonify(error="inference_failed", status="error"), 503
        blocked = risk >= artifact["threshold"]
        return jsonify(risk=risk, confidence=max(risk, 1.0 - risk),
                       confidence_kind="uncalibrated_class_score", type=attack_type(features, blocked),
                       type_method="FEATURE_HEURISTIC", decision="BLOCK" if blocked else "ALLOW",
                       analysis_method="MLP", model_version=artifact["model_version"],
                       dataset_source=artifact["dataset_source"], context=context,
                       threshold=artifact["threshold"], features=features)

    return app


if __name__ == "__main__":
    from waitress import serve

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--model", type=Path, default=BASE / "models" / "model.joblib")
    parser.add_argument("--rate-limit", type=int, default=120, help="Requests per sliding 60 seconds, per local caller IP")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.rate_limit <= 10000:
        parser.error("Invalid port or rate limit")
    app = create_app(args.model, args.rate_limit)
    print(f"CyberShield MLP listening on http://127.0.0.1:{args.port}", flush=True)
    serve(app, host="127.0.0.1", port=args.port, threads=4, connection_limit=32,
          backlog=32, channel_timeout=5, cleanup_interval=1, max_request_body_size=MAX_BODY_BYTES,
          max_request_header_size=8192, expose_tracebacks=False)
