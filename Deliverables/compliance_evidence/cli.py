"""Command-line interface (local only)."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

from .collector import load_state, normalize_state
from .evaluator import evaluate_all, summarize
from .report import findings_to_json, render_html, render_markdown


def _parse_frameworks(arg: str | None) -> set[str]:
    if not arg:
        return {"SOC2"}
    parts = {p.strip().upper() for p in arg.split(",") if p.strip()}
    # normalize keys used in code
    out: set[str] = set()
    for p in parts:
        if p in ("SOC2", "SOC 2"):
            out.add("SOC2")
        elif p in ("ISO27001", "ISO 27001"):
            out.add("ISO27001")
        elif p in ("PCI", "PCI_DSS", "PCI-DSS"):
            out.add("PCI_DSS")
        else:
            out.add(p)
    out.add("SOC2")
    return out


def cmd_audit(args: argparse.Namespace) -> int:
    raw = load_state(args.input)
    state = normalize_state(raw)
    frameworks = _parse_frameworks(args.frameworks)
    findings = evaluate_all(state, frameworks)
    md = render_markdown(findings, metadata=state.get("metadata"))

    if args.html_out:
        hpath = Path(args.html_out)
        hpath.parent.mkdir(parents=True, exist_ok=True)
        hpath.write_text(render_html(findings, metadata=state.get("metadata")), encoding="utf-8")
        print(f"Wrote HTML report: {args.html_out}")

    if args.out:
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(md, encoding="utf-8")
        print(f"Wrote Markdown report: {args.out}")
    else:
        print(md)

    if args.json_out:
        jpath = Path(args.json_out)
        jpath.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "summary": summarize(findings),
            "findings": findings_to_json(findings),
        }
        jpath.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Wrote JSON results: {args.json_out}")
    return 0


def _fingerprint(state: dict) -> str:
    blob = json.dumps(state, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def cmd_watch(args: argparse.Namespace) -> int:
    """S2: re-load fixture and print when compliance summary changes."""
    interval = max(5, int(args.interval))
    last_fp: str | None = None
    last_summary: dict | None = None
    print(f"Watching {args.input} every {interval}s (Ctrl+C to stop).", file=sys.stderr)
    while True:
        raw = load_state(args.input)
        state = normalize_state(raw)
        fp = _fingerprint(state)
        frameworks = _parse_frameworks(args.frameworks)
        findings = evaluate_all(state, frameworks)
        summary = summarize(findings)
        if last_fp is not None and (fp != last_fp or summary != last_summary):
            print(
                json.dumps(
                    {
                        "alert": "drift_or_change_detected",
                        "summary": summary,
                        "fingerprint": fp,
                    },
                    indent=2,
                )
            )
        last_fp = fp
        last_summary = summary
        time.sleep(interval)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="compliance-evidence",
        description="Local SOC 2-style evidence evaluation from JSON fixtures.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pa = sub.add_parser("audit", help="Evaluate controls and write report.")
    pa.add_argument("--input", "-i", required=True, help="Path to infrastructure JSON fixture.")
    pa.add_argument("--out", "-o", help="Write Markdown report to this path.")
    pa.add_argument("--html-out", help="Write self-contained HTML report to this path.")
    pa.add_argument("--json-out", help="Write machine-readable findings JSON.")
    pa.add_argument(
        "--frameworks",
        help="Comma-separated: SOC2, ISO27001, PCI_DSS (stretch mapping). Default: SOC2.",
    )
    pa.set_defaults(func=cmd_audit)

    pw = sub.add_parser("watch", help="Poll fixture file for changes (local continuous check).")
    pw.add_argument("--input", "-i", required=True, help="Path to infrastructure JSON fixture.")
    pw.add_argument("--interval", type=int, default=30, help="Seconds between checks (min 5).")
    pw.add_argument("--frameworks", help="Same as audit command.")
    pw.set_defaults(func=cmd_watch)

    return p


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
