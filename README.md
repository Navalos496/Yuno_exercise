# Yuno — SOC 2 evidence collection engine (local)

Small Python utility that reads **mock AWS-shaped JSON**, scores three Security (Common Criteria) style controls (**CC6.1**, **CC6.7**, **CC7.2**), and prints an **auditor-facing** Markdown or HTML pack. I kept the scope tight on purpose: a few checks we can defend beat a wall of guesses.

No cloud credentials are required for the default path.

## How this lines up with the rubric (short version)

- **Compliance logic:** rules are spelled out in code *and* in `DESIGN_DECISIONS.md`. We split **blocking** findings from **review notes** so empty exports do not silently “pass.”
- **Architecture:** ingestion, mapping text, per-control modules, reporting, and redaction are separate folders/files—see below.
- **Reports:** executive summary + glossary + “must fix” vs “review queue,” with ARN redaction before anything hits disk.
- **Edge cases / privacy:** missing MFA facts, missing buckets, empty CloudTrail maps, and half-filled S3 flags route to warnings or **manual review**, not made-up certainty.

## Requirements

- Python **3.10+**
- `pytest` if you want to run the tests (`requirements.txt` lists it)

## Setup

```powershell
cd Ejercicio
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

Print Markdown to the terminal:

```bash
python -m compliance_evidence audit -i fixtures/violations.json
```

Write Markdown, HTML, and JSON in one go:

```bash
python -m compliance_evidence audit -i fixtures/compliant.json -o sample_reports/audit_compliant.md --html-out sample_reports/audit_compliant.html --json-out sample_reports/results_compliant.json
```

Multi-framework tags (SOC 2 stays primary):

```bash
python -m compliance_evidence audit -i fixtures/compliant.json --frameworks SOC2,ISO27001,PCI_DSS -o sample_reports/audit_compliant_multifw.md
```

**Watch mode** (polls a JSON file; prints JSON when the scorecard changes—handy for demos):

```bash
python -m compliance_evidence watch -i fixtures/violations.json --interval 15
```

## Tests

```bash
python -m pytest tests/ -q
```

## Fixtures

| File | Intent |
|------|--------|
| `fixtures/compliant.json` | Happy path |
| `fixtures/violations.json` | Obvious breaks (admin `*:*`, MFA off, encryption off, CloudTrail gaps) |
| `fixtures/edge_cases.json` | Softer stories (SSE-S3 vs KMS hints, bad algorithm string, missing MFA columns) |
| `fixtures/incomplete_evidence.json` | Half-empty export to prove we flag **manual review** instead of guessing |

## Architecture (where to edit what)

1. **`compliance_evidence/collector.py`** — load JSON, normalize missing top-level keys.
2. **`compliance_evidence/mapping.py`** — SOC 2 blurbs + optional ISO/PCI tag map.
3. **`compliance_evidence/checks/`** — one module per control family (`iam.py`, `encryption.py`, `monitoring.py`) plus `bulk.py` orchestration and `status_resolve.py` for verdict math.
4. **`compliance_evidence/contracts.py`** — `Protocol` stubs for whoever adds Azure/GCP collectors later.
5. **`compliance_evidence/redact.py`** — trim ARNs/emails before reports.
6. **`compliance_evidence/report.py`** — Markdown + HTML + JSON export shape.
7. **`compliance_evidence/cli.py`** — `audit` / `watch` entrypoints.

`evaluator.py` is now just a thin import shim so older commands still work.

Read **`DESIGN_DECISIONS.md`** for the “why” on least-privilege, encryption calls, and monitoring gaps.

## Sample output

Regenerate anytime; committed samples live under `sample_reports/`.

| Sample | Use |
|--------|-----|
| `sample_reports/audit_compliant.md` / `.html` | All controls pass |
| `sample_reports/audit_violations.md` / `.html` | Failures + remediation text |
| `sample_reports/audit_edge_cases.md` / `.html` | Warnings / edge cases |
| `sample_reports/audit_incomplete.md` / `.html` | Thin evidence → manual review |
| `sample_reports/results_violations.json` | Machine-readable same run |

**Template + short annotated example:** see [`docs/AUDIT_REPORT_GUIDE.md`](docs/AUDIT_REPORT_GUIDE.md) (how the report maps to the spec, blank outline, and a trimmed filled example). **PDF:** open the `.html` in a browser → Print → Save as PDF.

## Submission bundle

A ready-to-zip copy (with its own `.git`) lives in **`Deliverables/`**. Re-copy from the repo root after big edits if you need that bundle to match `main` again.
