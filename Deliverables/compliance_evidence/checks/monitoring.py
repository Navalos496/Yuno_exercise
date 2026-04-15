"""CC7.2 — monitoring signal we modeled as CloudTrail coverage + log landing zone hints."""

from __future__ import annotations

from typing import Any

from ..mapping import CONTROL_BY_ID, SECONDARY_MAP
from ..models import ControlFinding
from .status_resolve import resolve


def evaluate_cc7_2(state: dict[str, Any], frameworks: set[str]) -> ControlFinding:
    ctl = CONTROL_BY_ID["CC7.2"]
    ct = state.get("cloudtrail") or {}
    regions_cfg = ct.get("regions") or {}
    required = ct.get("regions_required")
    if not required:
        required = sorted(regions_cfg.keys())

    blocking: list[str] = []
    advisory: list[str] = []
    manual_review = False

    if not regions_cfg and not required:
        manual_review = True
        advisory.append(
            "CloudTrail section is basically empty. Before anyone calls this a pass, you need at least one "
            "region worth of `DescribeTrails` / `GetTrailStatus` output in the bundle."
        )

    for region in required:
        if region not in regions_cfg:
            blocking.append(f"Required region `{region}` is missing from the CloudTrail map.")
            continue
        info = regions_cfg.get(region) or {}
        if not info.get("enabled"):
            blocking.append(f"Region `{region}` does not show an enabled trail.")
        elif not info.get("is_logging"):
            blocking.append(
                f"Region `{region}` has a trail object, yet `is_logging` is false. "
                "That is the same as having a smoke detector with the battery pulled out."
            )

    if ct.get("log_archive_bucket_configured") is False:
        advisory.append(
            "`log_archive_bucket_configured` is false. Logs might still exist, but you will be asked "
            "where they land and who can delete them."
        )
    elif ct.get("log_archive_bucket_configured") is None:
        advisory.append(
            "No statement about centralized log storage. Not an automatic fail, yet auditors will ask "
            "for the bucket name, retention, and object lock details."
        )

    if ct.get("requires_manual_review"):
        manual_review = True

    status = resolve(blocking=blocking, manual_review=manual_review, advisory=advisory)

    evidence = {
        "regions_required": list(required),
        "regions": regions_cfg,
        "multi_region_trail": ct.get("multi_region_trail"),
        "log_archive_bucket_configured": ct.get("log_archive_bucket_configured"),
    }

    recs: list[str] = []
    if blocking:
        recs.append("Enable logging in every in-scope region, or ship an org trail with proof it covers the regions you promise customers.")
    if advisory:
        recs.append("Add one paragraph to the audit packet: trail home region, log bucket ARN pattern, retention days, and who can edit bucket policies.")

    mapped = {"SOC2": [ctl.id]}
    sec = SECONDARY_MAP.get(ctl.id, {})
    if "ISO27001" in frameworks:
        mapped["ISO27001"] = sec.get("ISO27001", [])
    if "PCI_DSS" in frameworks:
        mapped["PCI_DSS"] = sec.get("PCI_DSS", [])

    return ControlFinding(
        control_id=ctl.id,
        control_title=ctl.title,
        tsc_category=ctl.tsc_category,
        status=status,
        plain_summary=(
            "CloudTrail is our proxy for 'do we have an audit log of API activity'. "
            "If the JSON is thin, we say so instead of pretending everything is fine."
        ),
        evidence=evidence,
        blocking_findings=blocking,
        review_notes=advisory,
        recommendations=recs,
        mapped_frameworks=mapped,
    )
