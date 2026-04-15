"""SOC 2 Trust Service Criteria mapping (subset for exercise)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Soc2Control:
    id: str
    title: str
    tsc_category: str
    auditor_context: str


# Subset aligned with scenario; IDs follow AICPA TSC naming used in practice.
CONTROLS: tuple[Soc2Control, ...] = (
    Soc2Control(
        id="CC6.1",
        title="Logical access to in-scope assets",
        tsc_category="Security (Common Criteria)",
        auditor_context=(
            "IAM is the front door to the cloud API. Auditors want to see that everyday access is narrow, "
            "privileged access is rare, and MFA exists for humans (or an IdP you can prove covers the same risk)."
        ),
    ),
    Soc2Control(
        id="CC6.7",
        title="Encryption of data at rest",
        tsc_category="Security (Common Criteria)",
        auditor_context=(
            "Disks walk away, buckets get mis-shared, and backups linger for years. "
            "Encryption at rest is the cheap insurance policy everyone expects to see switched on."
        ),
    ),
    Soc2Control(
        id="CC7.2",
        title="Security monitoring and detection",
        tsc_category="Security (Common Criteria)",
        auditor_context=(
            "If nobody logged the API call, the investigation stops cold. CloudTrail (or an equivalent) "
            "is how you prove someone did—or did not—touch production settings."
        ),
    ),
)

CONTROL_BY_ID: dict[str, Soc2Control] = {c.id: c for c in CONTROLS}


# Stretch S1: optional cross-framework hints (same check, different catalog).
SECONDARY_MAP: dict[str, dict[str, list[str]]] = {
    "CC6.7": {
        "ISO27001": ["A.10.1.1"],
        "PCI_DSS": ["3.4"],
    },
    "CC6.1": {
        "ISO27001": ["A.9.2.1", "A.9.4.1"],
        "PCI_DSS": ["7.1", "7.2"],
    },
    "CC7.2": {
        "ISO27001": ["A.12.4.1"],
        "PCI_DSS": ["10.1", "10.2"],
    },
}
