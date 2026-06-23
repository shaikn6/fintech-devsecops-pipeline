#!/usr/bin/env python3
"""Generate a weekly compliance report from Trivy and other scan outputs."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return {}


def parse_trivy(data: dict) -> tuple[int, int, int]:
    """Return (critical, high, total) vuln counts from a Trivy JSON report."""
    critical = high = total = 0
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            sev = vuln.get("Severity", "").upper()
            total += 1
            if sev == "CRITICAL":
                critical += 1
            elif sev == "HIGH":
                high += 1
    return critical, high, total


def compute_score(critical: int, high: int) -> int:
    score = 100
    score -= critical * 10
    score -= high * 3
    return max(0, score)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vuln-file", default="")
    parser.add_argument("--output-html", default="weekly-compliance-report.html")
    parser.add_argument("--output-json", default="weekly-compliance-report.json")
    parser.add_argument("--framework", default="pci-dss,soc2,cis-kubernetes")
    parser.add_argument("--report-type", default="weekly")
    parser.add_argument("--run-id", default="")
    args = parser.parse_args()

    trivy_data = load_json(args.vuln_file) if args.vuln_file else {}
    critical, high, total = parse_trivy(trivy_data)
    score = compute_score(critical, high)
    now = datetime.now(timezone.utc).isoformat()

    report = {
        "report_type": args.report_type,
        "run_id": args.run_id,
        "generated_at": now,
        "frameworks": args.framework.split(","),
        "overall_score": score,
        "critical_findings": critical,
        "high_findings": high,
        "total_findings": total,
    }

    Path(args.output_json).write_text(json.dumps(report, indent=2))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Compliance Report</title></head>
<body>
<h1>Weekly Compliance Report</h1>
<p><strong>Generated:</strong> {now}</p>
<p><strong>Run ID:</strong> {args.run_id}</p>
<p><strong>Frameworks:</strong> {args.framework}</p>
<h2>Summary</h2>
<table border="1" cellpadding="6">
  <tr><th>Overall Score</th><td>{score}%</td></tr>
  <tr><th>Critical Findings</th><td>{critical}</td></tr>
  <tr><th>High Findings</th><td>{high}</td></tr>
  <tr><th>Total Findings</th><td>{total}</td></tr>
</table>
</body>
</html>"""
    Path(args.output_html).write_text(html)

    print(f"Report written: score={score}% critical={critical} high={high} total={total}")
    sys.exit(0)


if __name__ == "__main__":
    main()
