"""Run all registered checks and roll up counts for the cover page."""

from __future__ import annotations

from typing import Any

from ..models import ComplianceStatus, ControlFinding
from .encryption import evaluate_cc6_7
from .iam import evaluate_cc6_1
from .monitoring import evaluate_cc7_2

# Tuple keeps ordering stable for reports; swap in new callables as the library grows.
EVALUATORS = (
    evaluate_cc6_1,
    evaluate_cc6_7,
    evaluate_cc7_2,
)


def evaluate_all(state: dict[str, Any], frameworks: set[str] | None = None) -> list[ControlFinding]:
    fw = frameworks or {"SOC2"}
    return [fn(state, fw) for fn in EVALUATORS]


def summarize(findings: list[ControlFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.status.value] = counts.get(f.status.value, 0) + 1
    return counts
