"""CC6.1 — logical access (IAM posture + MFA signals we can actually see in a fixture)."""

from __future__ import annotations

from typing import Any

from ..mapping import CONTROL_BY_ID, SECONDARY_MAP
from ..models import ComplianceStatus, ControlFinding
from . import iam_rules as R
from .status_resolve import resolve


def evaluate_cc6_1(state: dict[str, Any], frameworks: set[str]) -> ControlFinding:
    ctl = CONTROL_BY_ID["CC6.1"]
    iam = state.get("iam") or {}
    policies = iam.get("policies") or []

    blocking: list[str] = []
    advisory: list[str] = []
    manual_review = False

    skip_policy_scan = bool(iam.get("skip_policy_evaluation", False))
    if not skip_policy_scan and not policies:
        manual_review = True
        advisory.append(
            "Snapshot did not include any IAM customer-managed policies. "
            "That is normal for tiny demos, but for an audit you still need to show how access is granted "
            "(inline policies, permission sets, or attached AWS managed policies gathered elsewhere)."
        )

    for pol in policies:
        pname = pol.get("policy_name", "unknown")
        for stmt in pol.get("statement") or []:
            msg = R.full_admin_star_star(stmt)
            if msg:
                blocking.append(f"Policy '{pname}': {msg}")
            msg = R.action_star_scoped_resource(stmt)
            if msg:
                advisory.append(f"Policy '{pname}': {msg}")
            msg = R.service_level_wildcard(stmt)
            if msg:
                advisory.append(f"Policy '{pname}': {msg}")

    root_mfa = iam.get("root_mfa_enabled")
    if root_mfa is False:
        blocking.append("Root user MFA is off. Auditors treat that as an easy win to fix.")
    elif root_mfa is None:
        advisory.append(
            "We did not get a yes/no for root MFA. I am not going to guess—someone needs to paste the "
            "account summary screen or the API output that proves root is either protected or unused."
        )

    users = iam.get("users")
    if users is None:
        advisory.append(
            "Human IAM users were not listed, so we cannot prove console MFA coverage. "
            "If you rely on SSO only, say that in the narrative and map evidence to IdP MFA instead."
        )
    else:
        for u in users:
            if u.get("mfa_enabled") is False:
                blocking.append(
                    f"User '{u.get('name', 'unknown')}' is modeled as a person without MFA. "
                    "Service accounts should live under `roles`, not this list."
                )

    if iam.get("requires_manual_review"):
        manual_review = True

    status = resolve(blocking=blocking, manual_review=manual_review, advisory=advisory)

    evidence = {
        "policy_count": len(policies),
        "policy_names": [p.get("policy_name") for p in policies],
        "root_mfa_enabled": root_mfa,
        "human_users_included": users is not None,
        "human_user_count": len(users) if users is not None else None,
    }

    recs: list[str] = []
    if blocking:
        recs.append(
            "Remove *:* style policies except true emergency roles, and guard them with approval + logging."
        )
        recs.append("Turn MFA on for root and every human principal; enforce with `aws iam update-account-password-policy`.")
    if manual_review or advisory:
        recs.append(
            "Attach a short note for the QSA: who collects IAM/SSO evidence, how often, and where break-glass lives."
        )

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
            "We look for obvious administrative wildcards, service-wide `s3:*` style shortcuts, "
            "and the few MFA facts the JSON snapshot actually contains. Anything missing is called out "
            "instead of silently passing."
        ),
        evidence=evidence,
        blocking_findings=blocking,
        review_notes=advisory,
        recommendations=recs,
        mapped_frameworks=mapped,
    )
