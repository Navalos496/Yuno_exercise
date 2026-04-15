from __future__ import annotations

import json
from pathlib import Path

from compliance_evidence.checks.bulk import evaluate_all
from compliance_evidence.checks.iam_rules import full_admin_star_star
from compliance_evidence.models import ComplianceStatus
from compliance_evidence.redact import redact_value

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _load(name: str) -> dict:
    with (FIXTURES / name).open(encoding="utf-8") as fh:
        return json.load(fh)


def test_compliant_snapshot_passes_cleanly():
    state = _load("compliant.json")
    findings = evaluate_all(state)
    assert all(f.status == ComplianceStatus.COMPLIANT for f in findings)


def test_violations_surface_real_failures():
    state = _load("violations.json")
    findings = evaluate_all(state)
    assert all(f.status == ComplianceStatus.NON_COMPLIANT for f in findings)
    cc61 = next(f for f in findings if f.control_id == "CC6.1")
    joined = " ".join(cc61.blocking_findings).lower()
    assert "action *" in joined and "resource *" in joined


def test_incomplete_bundle_requests_human():
    state = _load("incomplete_evidence.json")
    findings = evaluate_all(state)
    assert any(f.status == ComplianceStatus.MANUAL_REVIEW for f in findings)


def test_star_star_with_condition_is_still_flagged():
    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*",
        "Condition": {"IpAddress": {"aws:SourceIp": ["203.0.113.0/24"]}},
    }
    msg = full_admin_star_star(stmt)
    assert msg is not None
    assert "Condition" in msg


def test_redact_masks_long_arn():
    sample = {"arn": "arn:aws:s3:::customer-data-bucket-7f3c/policy#foo"}
    out = redact_value(sample)
    assert out["arn"] != sample["arn"]


def test_action_star_without_resource_star_is_advisory_not_admin_pattern():
    from compliance_evidence.checks.iam_rules import action_star_scoped_resource

    stmt = {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::single-bucket/*"}
    msg = action_star_scoped_resource(stmt)
    assert msg is not None
    assert full_admin_star_star(stmt) is None
