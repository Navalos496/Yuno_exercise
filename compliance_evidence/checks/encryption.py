"""CC6.7 — encryption at rest for the pieces of AWS we modeled (S3 + RDS)."""

from __future__ import annotations

from typing import Any

from ..mapping import CONTROL_BY_ID, SECONDARY_MAP
from ..models import ControlFinding
from .status_resolve import resolve


def evaluate_cc6_7(state: dict[str, Any], frameworks: set[str]) -> ControlFinding:
    ctl = CONTROL_BY_ID["CC6.7"]
    s3b = (state.get("s3") or {}).get("buckets") or []
    rds_i = (state.get("rds") or {}).get("instances") or []

    blocking: list[str] = []
    advisory: list[str] = []
    manual_review = False

    if not s3b and not rds_i:
        manual_review = True
        advisory.append(
            "Neither S3 nor RDS objects were shipped in this file, so we cannot show encryption at rest "
            "for those services. That is not a pass—it means the story is unfinished unless other evidence exists."
        )

    for b in s3b:
        name = b.get("name", "?")
        enc = b.get("encryption") or {}
        if not enc.get("enabled"):
            blocking.append(f"Bucket `{name}` is not using default bucket encryption.")
        else:
            alg = (enc.get("algorithm") or "").upper()
            if alg in ("", "NONE"):
                blocking.append(
                    f"Bucket `{name}` claims encryption is on, but the algorithm field is empty or NONE. "
                    "That usually means the export script lied or the API response was trimmed."
                )
            elif alg == "AES256" and not enc.get("kms_key_id"):
                advisory.append(
                    f"Bucket `{name}` uses SSE-S3 (AES256). Plenty of audits accept it, "
                    "but some teams prefer a KMS CMK so key rotation and access boundaries are clearer."
                )
        pub = b.get("public_access_blocked")
        if pub is False:
            blocking.append(
                f"Bucket `{name}` does not have Block Public Access fully on. "
                "Even with encryption, public reads/writes are a separate nightmare."
            )
        elif pub is None:
            advisory.append(
                f"Bucket `{name}`: we never received the public access block flags. "
                "Treat that as homework for whoever owns the evidence pull."
            )

    for inst in rds_i:
        iid = inst.get("identifier", "?")
        if not inst.get("storage_encrypted"):
            blocking.append(f"RDS `{iid}` is running without storage encryption.")

    status = resolve(blocking=blocking, manual_review=manual_review, advisory=advisory)

    evidence = {
        "s3_bucket_count": len(s3b),
        "s3_buckets": [{"name": b.get("name"), "encryption": b.get("encryption")} for b in s3b[:12]],
        "s3_buckets_truncated": len(s3b) > 12,
        "rds_count": len(rds_i),
        "rds": [{"identifier": i.get("identifier"), "storage_encrypted": i.get("storage_encrypted")} for i in rds_i],
    }

    recs: list[str] = []
    if blocking:
        recs.append("Turn on default encryption for every bucket; fix any bucket that still shows `encryption: false`.")
        recs.append("Encrypt RDS storage and document which KMS key backs customer data.")
    if advisory:
        recs.append("Fill in missing JSON fields (public access blocks, algorithm) so the next run is decisive.")

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
            "S3 and RDS are stand-ins for 'data at rest'. We fail closed on missing encryption, "
            "nudge you on SSE-S3 vs KMS, and we refuse to invent a value when public access flags are absent."
        ),
        evidence=evidence,
        blocking_findings=blocking,
        review_notes=advisory,
        recommendations=recs,
        mapped_frameworks=mapped,
    )
