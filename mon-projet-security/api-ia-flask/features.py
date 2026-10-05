"""
Extraction de features pour le modèle ML (partagé entre entraînement et API).
Même ordre de colonnes pour train et inference.
"""
import re
import math
from collections import Counter

FEATURE_NAMES = [
    "length",
    "special_chars",
    "special_char_ratio",
    "sql_keywords",
    "has_union_pattern",
    "has_tautology",
    "has_time_based",
    "has_comment",
    "has_error_based",
    "entropy",
    "keyword_density",
]

SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete", "drop",
    "create", "alter", "from", "where", "and", "or", "join",
    "table", "database", "schema", "column", "index",
]


def normalize_input(s: str) -> str:
    if not s:
        return ""
    s = s.strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    freq = Counter(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def count_sql_keywords(s: str) -> int:
    lower = s.lower()
    count = 0
    for kw in SQL_KEYWORDS:
        if re.search(r"\b" + re.escape(kw) + r"\b", lower):
            count += 1
    return count


def extract_features_dict(input_str: str) -> dict:
    s = normalize_input(input_str)
    length = len(s)
    special_chars = len(re.findall(r"""['"=;#()\-*\/]""", s))
    special_char_ratio = special_chars / length if length > 0 else 0.0
    sql_kw = count_sql_keywords(s)
    has_union = 1 if re.search(r"\bunion\b.*\bselect\b", s) else 0
    has_tautology = 1 if re.search(r"1\s*=\s*1|'1'\s*=\s*'1'", s) else 0
    has_time_based = 1 if re.search(r"\b(sleep|benchmark|waitfor|delay)\b", s) else 0
    has_comment = 1 if re.search(r"--|#|/\*", s) else 0
    has_error_based = 1 if re.search(r"\b(extractvalue|updatexml|exp)\b", s) else 0
    entropy = shannon_entropy(s)
    word_count = len(s.split()) if s else 0
    keyword_density = sql_kw / word_count if word_count > 0 else 0.0

    return {
        "length": length,
        "special_chars": special_chars,
        "special_char_ratio": round(special_char_ratio, 3),
        "sql_keywords": sql_kw,
        "has_union_pattern": has_union,
        "has_tautology": has_tautology,
        "has_time_based": has_time_based,
        "has_comment": has_comment,
        "has_error_based": has_error_based,
        "entropy": entropy,
        "keyword_density": round(keyword_density, 3),
    }


def features_to_vector(features: dict) -> list:
    """Vecteur dans l'ordre FEATURE_NAMES pour le modèle."""
    return [features.get(name, 0) for name in FEATURE_NAMES]
