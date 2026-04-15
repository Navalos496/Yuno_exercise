"""Load and normalize infrastructure state from local JSON fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_state(path: Path | str) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"No fixture file: {p}")
    with p.open(encoding="utf-8") as f:
        return json.load(f)


def normalize_state(raw: dict[str, Any]) -> dict[str, Any]:
    """Ensure expected top-level keys exist for downstream evaluation."""
    return {
        "iam": raw.get("iam") or {},
        "s3": raw.get("s3") or {},
        "rds": raw.get("rds") or {},
        "cloudtrail": raw.get("cloudtrail") or {},
        "metadata": raw.get("metadata") or {},
    }
