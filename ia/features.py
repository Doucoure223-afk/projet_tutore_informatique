"""Versioned, bounded feature extraction for SQL-injection input classification."""

import re
import unicodedata
from urllib.parse import unquote

FEATURE_SCHEMA = "sqli-features-v1"
MAX_SQL_LENGTH = 8192
KEYWORDS = (
    "union", "select", "from", "where", "or", "and", "insert", "update",
    "delete", "drop", "alter", "create", "sleep", "benchmark", "waitfor",
    "extractvalue", "updatexml", "load_file", "outfile", "information_schema",
)
FEATURE_NAMES = (
    "length", "word_count", "single_quotes", "double_quotes", "semicolons",
    "comments", "equals", "parentheses", "keyword_count",
) + tuple("has_" + keyword for keyword in KEYWORDS) + (
    "logical_comparison", "tautology", "union_select", "stacked_statement",
    "quote_comment", "hex_literal", "encoded_input", "comment_obfuscation",
)


def normalize(value):
    """Decode at most three times; keep a comment-free and a compact SQL view."""
    if not isinstance(value, str) or len(value) > MAX_SQL_LENGTH:
        raise ValueError("sql must be a string of at most 8192 characters")
    decoded = unicodedata.normalize("NFKC", value)
    for _ in range(3):
        new_value = unquote(decoded, errors="replace")
        if new_value == decoded:
            break
        decoded = new_value
    decoded = decoded.lower()
    # MySQL executable comments contain active SQL, not disposable text.
    executable = re.sub(r"/\*![0-9]{0,6}\s*(.*?)\*/", r" \1 ", decoded, flags=re.S)
    spaced = re.sub(r"/\*.*?\*/", " ", executable, flags=re.S)
    compact = re.sub(r"/\*.*?\*/", "", executable, flags=re.S)
    return decoded, re.sub(r"\s+", " ", spaced).strip(), re.sub(r"\s+", " ", compact).strip()


def extract_features(value):
    decoded, spaced, compact = normalize(value)
    views = (spaced, compact)
    words = [word for view in views for word in re.findall(r"[a-z_]+", view)]
    word_set = set(words)
    present = {keyword: float(keyword in word_set) for keyword in KEYWORDS}
    comment_count = len(re.findall(r"--|#|/\*", decoded))
    features = {
        "length": min(len(decoded) / 256.0, 4.0),
        "word_count": min(len(re.findall(r"\w+", spaced)) / 32.0, 4.0),
        "single_quotes": min(decoded.count("'") / 8.0, 3.0),
        "double_quotes": min(decoded.count('"') / 8.0, 3.0),
        "semicolons": min(decoded.count(";") / 3.0, 3.0),
        "comments": min(comment_count / 3.0, 3.0),
        "equals": min(decoded.count("=") / 4.0, 3.0),
        "parentheses": min((decoded.count("(") + decoded.count(")")) / 8.0, 3.0),
        "keyword_count": sum(present.values()) / len(KEYWORDS),
    }
    features.update({"has_" + key: val for key, val in present.items()})
    features.update({
        "logical_comparison": float(any(re.search(r"\b(?:or|and)\b.{0,120}(?:=|<>|!=|\blike\b|\bbetween\b)", view) for view in views)),
        "tautology": float(any(re.search(r"\b(?:or|and)\s+(?:'(\w+)'\s*=\s*'\1'|(\d+)\s*=\s*\2\b)", view) for view in views)),
        "union_select": float(any(re.search(r"\bunion\s+(?:all\s+)?select\b", view) for view in views)),
        "stacked_statement": float(any(re.search(r";\s*(?:drop|delete|insert|update|alter|create|select|exec|waitfor)\b", view) for view in views)),
        "quote_comment": float(bool(re.search(r"['\"].{0,160}(?:--|#|/\*)", decoded))),
        "hex_literal": float(any(re.search(r"\b0x[0-9a-f]+\b", view) for view in views)),
        "encoded_input": float(decoded != unicodedata.normalize("NFKC", value).lower()),
        "comment_obfuscation": float(bool(re.search(r"\w/\*.*?\*/\w", decoded))),
    })
    return features


def vectorize(value):
    features = extract_features(value)
    return [features[name] for name in FEATURE_NAMES]


def attack_type(features, blocked):
    """Explanatory label only: the binary MLP does not learn attack families."""
    if not blocked:
        return "NORMAL"
    if features["has_sleep"] or features["has_benchmark"] or features["has_waitfor"]:
        return "TIME_BASED"
    if features["has_extractvalue"] or features["has_updatexml"]:
        return "ERROR_BASED"
    if features["union_select"]:
        return "UNION_BASED"
    if features["stacked_statement"] or features["has_drop"]:
        return "STACKED_QUERY"
    if features["logical_comparison"]:
        return "BOOLEAN_BASED"
    if features["quote_comment"]:
        return "COMMENT_INJECTION"
    return "SUSPICIOUS"
