"""Turn separate signal lists into a single status (automation should not fake certainty)."""

from __future__ import annotations

from ..models import ComplianceStatus


def resolve(
    *,
    blocking: list[str],
    manual_review: bool,
    advisory: list[str],
) -> ComplianceStatus:
    if blocking:
        return ComplianceStatus.NON_COMPLIANT
    if manual_review:
        return ComplianceStatus.MANUAL_REVIEW
    if advisory:
        return ComplianceStatus.WARNING
    return ComplianceStatus.COMPLIANT
