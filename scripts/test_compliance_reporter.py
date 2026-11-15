"""Deterministic unit tests for the weekly compliance reporter.

Run from the repo root:  python -m unittest discover -s scripts -p 'test_*.py'
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import compliance_reporter as cr

SCRIPT = Path(__file__).with_name("compliance_reporter.py")


class ComputeScore(unittest.TestCase):
    def test_clean_is_100(self):
        self.assertEqual(cr.compute_score(0, 0), 100)

    def test_severity_weights(self):
        # critical costs 10, high costs 3
        self.assertEqual(cr.compute_score(2, 3), 100 - 20 - 9)

    def test_floor_at_zero(self):
        self.assertEqual(cr.compute_score(50, 0), 0)


class ParseTrivy(unittest.TestCase):
    def test_counts_by_severity(self):
        data = {
            "Results": [
                {"Vulnerabilities": [
                    {"Severity": "CRITICAL"},
                    {"Severity": "high"},   # case-insensitive
                    {"Severity": "MEDIUM"},
                ]},
                {"Vulnerabilities": None},  # a clean result
                {},                          # a result with no key
            ]
        }
        self.assertEqual(cr.parse_trivy(data), (1, 1, 3))

    def test_empty_report(self):
        self.assertEqual(cr.parse_trivy({}), (0, 0, 0))


class MainCli(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True, text=True,
        )

    def test_happy_path_writes_report(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            vuln = d / "trivy.json"
            vuln.write_text(json.dumps({
                "Results": [{"Vulnerabilities": [
                    {"Severity": "CRITICAL"}, {"Severity": "HIGH"},
                ]}]
            }))
            out_json = d / "report.json"
            r = self._run(
                "--vuln-file", str(vuln),
                "--output-json", str(out_json),
                "--output-html", str(d / "report.html"),
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            report = json.loads(out_json.read_text())
            self.assertEqual(report["critical_findings"], 1)
            self.assertEqual(report["high_findings"], 1)
            self.assertEqual(report["overall_score"], 100 - 10 - 3)

    def test_missing_vuln_file_fails_loudly(self):
        r = self._run("--vuln-file", "/no/such/file.json")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not found", r.stderr)

    def test_corrupt_vuln_file_fails_loudly(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text("{not valid json")
            r = self._run("--vuln-file", str(bad))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("not valid JSON", r.stderr)


if __name__ == "__main__":
    unittest.main()
