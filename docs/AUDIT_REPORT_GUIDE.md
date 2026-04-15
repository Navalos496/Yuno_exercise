# Audit report — template, example, and export formats

This page shows **what the automated audit report looks like**, how it maps to the exercise requirements, and how to produce real files from the tool.

## How to generate a real report (not static examples)

From the project root:

| Format | Command |
|--------|---------|
| **Markdown** (easy to diff, email, or paste into Confluence) | `python -m compliance_evidence audit -i fixtures/violations.json -o my_report.md` |
| **HTML** (open in a browser; print to PDF if you need a PDF) | `python -m compliance_evidence audit -i fixtures/violations.json --html-out my_report.html` |
| **JSON** (for GRC tools or CI gates) | `python -m compliance_evidence audit -i fixtures/violations.json --json-out my_results.json` |
| **Terminal** (quick preview) | `python -m compliance_evidence audit -i fixtures/violations.json` |

The tool does **not** emit PDF directly. For auditors who want a PDF, open the HTML file in Chrome or Edge and use **Print → Save as PDF**.

**Pre-generated samples** in this repo (full length, from real fixtures):

- `sample_reports/audit_compliant.md` / `.html` — all controls pass  
- `sample_reports/audit_violations.md` / `.html` — multiple failures  
- `sample_reports/audit_edge_cases.md` / `.html` — mixed / review notes  
- `sample_reports/audit_incomplete.md` / `.html` — thin evidence, “needs human”  
- `sample_reports/results_violations.json` — same run as machine-readable output  

---

## Requirement checklist (what each section delivers)

| Requirement | Where it appears in the report |
|-------------|--------------------------------|
| **Summary** — how many controls compliant vs not | **Executive summary** (counts for Pass / Fail / Partial / Review / Needs human) |
| **Per-control findings** — evidence, status, issues | **Per-control results** — result badge, redacted evidence JSON, **Must fix** vs **Review queue** |
| **Actionable recommendations** | **What we would do next** (bullets per control; strongest when a control fails) |
| **Export format** auditor can use | **Markdown**, **HTML**, **JSON** (PDF via print-from-browser) |

---

## Part A — Blank template (structure only)

Use this as a checklist when adding controls or when explaining the layout to an auditor.

```markdown
# SOC 2 evidence report (automated)

**Generated:** {{UTC timestamp}}
**Environment label:** {{e.g. production-snapshot}}
**Evidence source:** {{e.g. local JSON fixture / collector job id}}

## Executive summary

We looked at **{{N}}** Security-type controls using the JSON snapshot on disk.
- **Pass:** {{count}}
- **Fail:** {{count}}
- **Partial:** {{count}}
- **Review (yellow flag):** {{count}}
- **Needs human judgement:** {{count}}

**How to read this:** (short legend for Pass / Fail / Review / Needs human)

Evidence blocks below are **redacted** (ARNs shortened, emails removed).

## Glossary (for people who do not live in AWS)

| Term | Plain language |
|------|----------------|
| **IAM** | … |
| … | … |

## Per-control results

### {{Control id}} — {{Control title}}

**Category:** {{TSC category}}  
**Result:** {{PASS | FAIL | …}} (`{{machine status}}`)

**Why this matters:**  
{{Auditor-facing context}}

**What the script actually checked:**  
{{One short paragraph}}

**Evidence excerpt (redacted JSON):**
```json
{ ... }
```

**Mapped frameworks:** (only if CLI asked for ISO/PCI tags)

**Must fix:** (blocking findings; or “none flagged automatically”)

**Review queue:** (missing data / judgement calls; or “empty”)

**What we would do next:** (remediation bullets)

---

(repeat per control)

## Honest limitations

(Point-in-time snapshot; Type II still needs history, sampling, interviews.)
```

---

## Part B — Short filled example (illustrative)

Below is a **trimmed** example: one control only, fictional timestamps, tone and section order match the generator. Your real file lists **all** evaluated controls (today: CC6.1, CC6.7, CC7.2).

```markdown
# SOC 2 evidence report (automated)

**Generated:** 2026-04-15 15:00 UTC  
**Environment label:** yuno-legacy-audit-drill  
**Evidence source:** local_fixture: violations.json  

## Executive summary

We looked at **3** Security-type controls using the JSON snapshot on disk.
- **Pass:** 0
- **Fail:** 3
- **Partial:** 0
- **Review (yellow flag):** 0
- **Needs human judgement:** 0

**How to read this:** *Fail* is for items we treat as objectively out of policy. *Needs human* means the file was too thin to grade fairly. *Review* is the middle ground—nothing exploded in automation, but a real person should still read the notes.

Evidence blocks below are **redacted** (ARNs shortened, emails removed) so the report is safer to email.

## Glossary (for people who do not live in AWS)

| Term | Plain language |
|------|----------------|
| **IAM** | The gatekeeper for cloud APIs: who is allowed to do what, and on which resources. |
| **Least-privilege** | Only handing out the permissions someone truly needs—not handing them the master keys "just in case". |

## Per-control results

### CC6.1 — Logical access to in-scope assets

**Category:** Security (Common Criteria)  
**Result:** FAIL (`non_compliant`)

**Why this matters:**  
IAM is the front door to the cloud API. Auditors want to see that everyday access is narrow, privileged access is rare, and MFA exists for humans (or an IdP you can prove covers the same risk).

**What the script actually checked:**  
We look for obvious administrative wildcards, service-wide `s3:*` style shortcuts, and the few MFA facts the JSON snapshot actually contains. Anything missing is called out instead of silently passing.

**Evidence excerpt (redacted JSON):**
```json
{
  "policy_count": 2,
  "policy_names": ["AdminAccess", "S3DangerousWildcard"],
  "root_mfa_enabled": false,
  "human_users_included": true,
  "human_user_count": 1
}
```

**Must fix (automation treated these as hard failures):**
- Policy 'AdminAccess': Allow grants Action * on Resource * (classic full-admin pattern).
- Root user MFA is off. Auditors treat that as an easy win to fix.
- User 'contractor-temp' is modeled as a person without MFA. Service accounts should live under `roles`, not this list.

**Review queue:** empty.

**What we would do next:**
- Remove *:* style policies except true emergency roles, and guard them with approval + logging.
- Turn MFA on for root and every human principal; enforce with `aws iam update-account-password-policy`.
- Attach a short note for the QSA: who collects IAM/SSO evidence, how often, and where break-glass lives.

---

### CC6.7 — …   _(same pattern: result, evidence, must fix / review queue, remediation)_
### CC7.2 — …   _(same pattern)_

## Honest limitations

This is still a **point-in-time** JSON snapshot. SOC 2 Type II wants proof over months, which means ticketing, change history, sampled log queries, and interviews—not just one file.
```

---

## JSON export shape (for tools, not humans)

The `--json-out` file wraps a **summary** plus an array of **findings**. Each finding includes `status`, `evidence_redacted`, `blocking_findings`, `review_notes`, and `recommendations`. Open `sample_reports/results_violations.json` for a full example.

---

## Summary

- **Template:** Part A — section headings and placeholders.  
- **What it looks like filled:** Part B + the real files under `sample_reports/`.  
- **PDF:** generate from **HTML** via the browser print dialog.
