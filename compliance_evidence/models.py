from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ComplianceStatus(str, Enum):
    """How a control scored for this snapshot. Not every gap is a hard fail."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    WARNING = "warning"
    MANUAL_REVIEW = "manual_review"
    UNKNOWN = "unknown"


@dataclass
class ControlFinding:
    """One control, one verdict, split so auditors see facts vs judgement calls."""

    control_id: str
    control_title: str
    tsc_category: str
    status: ComplianceStatus
    plain_summary: str
    evidence: dict[str, Any]
    blocking_findings: list[str] = field(default_factory=list)
    review_notes: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    mapped_frameworks: dict[str, list[str]] = field(default_factory=dict)
