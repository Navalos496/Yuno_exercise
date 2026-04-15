"""Generate auditor-oriented Markdown, HTML, and optional JSON."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any

from .evaluator import summarize
from .mapping import CONTROL_BY_ID
from .models import ComplianceStatus, ControlFinding
from .redact import redact_evidence

_GLOSSARY = """
## Glossary (for people who do not live in AWS)

| Term | Plain language |
|------|----------------|
| **IAM** | The gatekeeper for cloud APIs: who is allowed to do what, and on which resources. |
| **Least-privilege** | Only handing out the permissions someone truly needs—not handing them the master keys "just in case". |
| **S3 bucket** | A shared drive in the sky. Customer uploads, backups, and logs often land here. |
| **RDS** | A managed database where rows of business data live. |
| **CloudTrail** | A flight recorder for API calls—who changed what, and when. |
| **Encryption at rest** | Data is stored encrypted on disk so a lost volume or copied snapshot is not automatically readable. |
"""


def _status_badge(status: ComplianceStatus) -> str:
    return {
        ComplianceStatus.COMPLIANT: "PASS",
        ComplianceStatus.NON_COMPLIANT: "FAIL",
        ComplianceStatus.PARTIAL: "PARTIAL",
        ComplianceStatus.WARNING: "REVIEW",
        ComplianceStatus.MANUAL_REVIEW: "NEEDS HUMAN",
        ComplianceStatus.UNKNOWN: "UNKNOWN",
    }[status]


def _status_class(status: ComplianceStatus) -> str:
    return {
        ComplianceStatus.COMPLIANT: "pass",
        ComplianceStatus.NON_COMPLIANT: "fail",
        ComplianceStatus.PARTIAL: "partial",
        ComplianceStatus.WARNING: "warn",
        ComplianceStatus.MANUAL_REVIEW: "manual",
        ComplianceStatus.UNKNOWN: "unknown",
    }[status]


def render_markdown(
    findings: list[ControlFinding],
    metadata: dict[str, Any] | None = None,
) -> str:
    meta = metadata or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = summarize(findings)
    total = len(findings)
    lines: list[str] = [
        "# SOC 2 evidence report (automated)",
        "",
        f"**Generated:** {now}",
        f"**Environment label:** {meta.get('environment', 'unspecified')}",
        f"**Evidence source:** {meta.get('evidence_source', 'local JSON fixture')}",
        "",
        "## Executive summary",
        "",
        f"We looked at **{total}** Security-type controls using the JSON snapshot on disk.",
        f"- **Pass:** {counts.get(ComplianceStatus.COMPLIANT.value, 0)}",
        f"- **Fail:** {counts.get(ComplianceStatus.NON_COMPLIANT.value, 0)}",
        f"- **Partial:** {counts.get(ComplianceStatus.PARTIAL.value, 0)}",
        f"- **Review (yellow flag):** {counts.get(ComplianceStatus.WARNING.value, 0)}",
        f"- **Needs human judgement:** {counts.get(ComplianceStatus.MANUAL_REVIEW.value, 0)}",
        "",
        "**How to read this:** *Fail* is for items we treat as objectively out of policy. "
        "*Needs human* means the file was too thin to grade fairly. "
        "*Review* is the middle ground—nothing exploded in automation, but a real person should still read the notes.",
        "",
        "Evidence blocks below are **redacted** (ARNs shortened, emails removed) so the report is safer to email.",
        "",
        _GLOSSARY.strip(),
        "",
        "## Per-control results",
        "",
    ]

    for f in findings:
        ctl = CONTROL_BY_ID.get(f.control_id)
        ctx = ctl.auditor_context if ctl else ""
        safe_evidence = redact_evidence(f.evidence)
        lines.extend(
            [
                f"### {f.control_id} — {f.control_title}",
                "",
                f"**Category:** {f.tsc_category}  ",
                f"**Result:** {_status_badge(f.status)} (`{f.status.value}`)",
                "",
                "**Why this matters:**",
                ctx,
                "",
                "**What the script actually checked:**",
                f.plain_summary,
                "",
                "**Evidence excerpt (redacted JSON):**",
                "```json",
                json.dumps(safe_evidence, indent=2),
                "```",
                "",
            ]
        )
        if f.mapped_frameworks:
            lines.append("**Mapped frameworks (only when you asked for them on the CLI):**")
            for fw, ids in f.mapped_frameworks.items():
                lines.append(f"- **{fw}:** {', '.join(ids) if ids else '—'}")
            lines.append("")

        if f.blocking_findings:
            lines.append("**Must fix (automation treated these as hard failures):**")
            for issue in f.blocking_findings:
                lines.append(f"- {issue}")
            lines.append("")
        else:
            lines.append("**Must fix:** none flagged automatically.")
            lines.append("")

        if f.review_notes:
            lines.append("**Review queue (missing data, judgement calls, softer risks):**")
            for note in f.review_notes:
                lines.append(f"- {note}")
            lines.append("")
        else:
            lines.append("**Review queue:** empty.")
            lines.append("")

        if f.recommendations:
            lines.append("**What we would do next:**")
            for r in f.recommendations:
                lines.append(f"- {r}")
            lines.append("")

        lines.append("---")
        lines.append("")

    lines.append(
        "## Honest limitations\n\n"
        "This is still a **point-in-time** JSON snapshot. SOC 2 Type II wants proof over months, "
        "which means ticketing, change history, sampled log queries, and interviews—not just one file."
    )
    return "\n".join(lines)


def render_html(
    findings: list[ControlFinding],
    metadata: dict[str, Any] | None = None,
) -> str:
    meta = metadata or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = summarize(findings)
    total = len(findings)

    rows = []
    for term, desc in [
        ("IAM", "Gatekeeper for cloud APIs."),
        ("Least-privilege", "Handing out the smallest permission set that still lets people work."),
        ("S3 bucket", "Shared object storage—often customer files or backups."),
        ("RDS", "Managed relational databases."),
        ("CloudTrail", "API flight recorder."),
        ("Encryption at rest", "Data stored encrypted on disk."),
    ]:
        rows.append(f"<tr><th>{html.escape(term)}</th><td>{html.escape(desc)}</td></tr>")

    cards: list[str] = []
    for f in findings:
        ctl = CONTROL_BY_ID.get(f.control_id)
        ctx = html.escape(ctl.auditor_context if ctl else "")
        badge = _status_badge(f.status)
        cls = _status_class(f.status)
        safe_evidence = redact_evidence(f.evidence)

        def _ul(items: list[str]) -> str:
            if not items:
                return "<p>None.</p>"
            return "<ul>" + "".join(f"<li>{html.escape(i)}</li>" for i in items) + "</ul>"

        recs_html = (
            "<ul>" + "".join(f"<li>{html.escape(r)}</li>" for r in f.recommendations) + "</ul>"
            if f.recommendations
            else "<p>—</p>"
        )
        fw_html = ""
        if f.mapped_frameworks:
            parts = [
                f"<li><strong>{html.escape(k)}:</strong> {html.escape(', '.join(v) if v else '—')}</li>"
                for k, v in f.mapped_frameworks.items()
            ]
            fw_html = "<h4>Mapped frameworks</h4><ul>" + "".join(parts) + "</ul>"

        cards.append(
            f"""
<section class="card">
  <h3>{html.escape(f.control_id)} — {html.escape(f.control_title)}</h3>
  <p class="meta">{html.escape(f.tsc_category)}</p>
  <p class="badge {cls}"><span>{html.escape(badge)}</span> <code>{html.escape(f.status.value)}</code></p>
  <h4>Why this matters</h4>
  <p>{ctx}</p>
  <h4>What we checked</h4>
  <p>{html.escape(f.plain_summary)}</p>
  <h4>Evidence excerpt (redacted)</h4>
  <pre class="json">{html.escape(json.dumps(safe_evidence, indent=2))}</pre>
  {fw_html}
  <h4>Must fix</h4>
  {_ul(f.blocking_findings)}
  <h4>Review queue</h4>
  {_ul(f.review_notes)}
  <h4>What we would do next</h4>
  {recs_html}
</section>
"""
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SOC 2 evidence report (automated)</title>
  <style>
    body {{ font-family: Georgia, "Times New Roman", serif; line-height: 1.5; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #111; }}
    h1, h2, h3, h4 {{ font-family: system-ui, sans-serif; line-height: 1.25; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; font-family: system-ui, sans-serif; }}
    th, td {{ border: 1px solid #bbb; padding: 0.5rem 0.6rem; text-align: left; vertical-align: top; }}
    th {{ width: 22%; background: #f4f4f4; }}
    .summary span {{ display: inline-block; margin-right: 1.25rem; font-family: system-ui, sans-serif; }}
    .card {{ border: 1px solid #ccc; border-radius: 8px; padding: 1rem 1.25rem; margin: 1.5rem 0; background: #fafafa; }}
    .meta {{ color: #444; margin-top: 0; font-family: system-ui, sans-serif; font-size: 0.95rem; }}
    .badge span {{ font-weight: 700; padding: 0.2rem 0.55rem; border-radius: 4px; font-family: system-ui, sans-serif; }}
    .pass span {{ background: #d4edda; color: #155724; }}
    .fail span {{ background: #f8d7da; color: #721c24; }}
    .partial span {{ background: #fff3cd; color: #856404; }}
    .warn span {{ background: #cce5ff; color: #004085; }}
    .manual span {{ background: #e7d5f5; color: #4a235a; }}
    .unknown span {{ background: #e2e3e5; color: #383d41; }}
    pre.json {{ background: #111; color: #eaeaea; padding: 1rem; overflow: auto; border-radius: 6px; font-size: 0.85rem; }}
    code {{ font-size: 0.9em; }}
  </style>
</head>
<body>
  <h1>SOC 2 evidence report (automated)</h1>
  <p><strong>Generated:</strong> {html.escape(now)}<br/>
     <strong>Environment:</strong> {html.escape(str(meta.get("environment", "unspecified")))}<br/>
     <strong>Evidence source:</strong> {html.escape(str(meta.get("evidence_source", "local JSON fixture")))}</p>

  <h2>Executive summary</h2>
  <p>We evaluated <strong>{total}</strong> Security-style controls from the JSON snapshot.</p>
  <p class="summary">
    <span><strong>Pass:</strong> {counts.get(ComplianceStatus.COMPLIANT.value, 0)}</span>
    <span><strong>Fail:</strong> {counts.get(ComplianceStatus.NON_COMPLIANT.value, 0)}</span>
    <span><strong>Partial:</strong> {counts.get(ComplianceStatus.PARTIAL.value, 0)}</span>
    <span><strong>Review:</strong> {counts.get(ComplianceStatus.WARNING.value, 0)}</span>
    <span><strong>Needs human:</strong> {counts.get(ComplianceStatus.MANUAL_REVIEW.value, 0)}</span>
  </p>
  <p><em>Evidence sections are redacted so ARNs and stray emails do not travel in plaintext.</em></p>

  <h2>Glossary</h2>
  <table><tbody>{"".join(rows)}</tbody></table>

  <h2>Per-control results</h2>
  {"".join(cards)}

  <h2>Limitations</h2>
  <p>This file proves what the JSON said at generation time. Type II work still needs history, sampling, and interviews.</p>
</body>
</html>
"""


def findings_to_json(findings: list[ControlFinding]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings:
        out.append(
            {
                "control_id": f.control_id,
                "control_title": f.control_title,
                "tsc_category": f.tsc_category,
                "status": f.status.value,
                "plain_summary": f.plain_summary,
                "evidence_redacted": redact_evidence(f.evidence),
                "blocking_findings": f.blocking_findings,
                "review_notes": f.review_notes,
                "recommendations": f.recommendations,
                "mapped_frameworks": f.mapped_frameworks,
            }
        )
    return out
