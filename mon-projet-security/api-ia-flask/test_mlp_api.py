"""Test rapide : chargement MLP + prédiction."""
from app import app, ML_MODEL
from features import extract_features_dict, features_to_vector
import numpy as np

print("ML_MODEL charge:", "OK" if ML_MODEL else "NON")
model = ML_MODEL.get("model") if ML_MODEL else None
print("predict_proba:", hasattr(model, "predict_proba") if model else "N/A")

if model:
    # Test SQLi
    f = extract_features_dict("1' OR '1'='1")
    v = np.array([features_to_vector(f)], dtype=np.float64)
    p = model.predict_proba(v)[0]
    print("Payload SQLi -> proba[1]:", round(p[1], 4))

    # Test bénin
    f2 = extract_features_dict("hello world")
    v2 = np.array([features_to_vector(f2)], dtype=np.float64)
    p2 = model.predict_proba(v2)[0]
    print("Bénin -> proba[1]:", round(p2[1], 4))

print("OK")
