"""Strip or shorten sensitive strings before they land in an auditor report."""

from __future__ import annotations

import copy
import re
from typing import Any

# S3 bucket ARNs often skip the account field (arn:aws:s3:::name). Other services include :123456789012:.
_ARN = re.compile(r"arn:aws:[^\s\],}\"]+", re.I)
_KMS = re.compile(r"arn:aws:kms:[^\"\s]+", re.I)
_EMAIL = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")


def _mask_arn(m: re.Match[str]) -> str:
    s = m.group(0)
    if len(s) <= 28:
        return "arn:aws:…(redacted)"
    return s[:22] + "…" + s[-12:]


def redact_value(value: Any) -> Any:
    """Recursively walk JSON-like structures and mask obvious secrets/identifiers."""
    if isinstance(value, str):
        v = _EMAIL.sub("[email redacted]", value)
        v = _KMS.sub("arn:aws:kms:…(redacted)", v)
        v = _ARN.sub(_mask_arn, v)
        return v
    if isinstance(value, list):
        return [redact_value(x) for x in value]
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    return value


def redact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Copy + redact so the original evaluator output stays untouched in memory."""
    return redact_value(copy.deepcopy(evidence))
