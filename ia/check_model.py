"""Print the version stored in a serialized CyberShield model."""

import sys
from pathlib import Path

import joblib


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_model.py MODEL_PATH", file=sys.stderr)
        return 2
    try:
        artifact = joblib.load(Path(sys.argv[1]))
    except Exception as error:
        print(f"Cannot read model artifact: {type(error).__name__}", file=sys.stderr)
        return 1
    if not isinstance(artifact, dict) or not isinstance(artifact.get("model_version"), str):
        print("Model artifact has no version.", file=sys.stderr)
        return 1
    print(artifact["model_version"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
